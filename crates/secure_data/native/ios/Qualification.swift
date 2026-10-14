import UIKit
import Foundation
import Security
import CryptoKit
import LocalAuthentication

private enum QualificationFailure: Error { case unexpectedSuccess, assertionFailed }

@main final class QualificationDelegate: UIResponder, UIApplicationDelegate {
    var window: UIWindow?
    func application(_ application: UIApplication, didFinishLaunchingWithOptions options: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let window = UIWindow()
        window.rootViewController = UIViewController(); window.makeKeyAndVisible(); self.window = window
        DispatchQueue.global(qos: .userInitiated).async { self.runQualification() }
        return true
    }
    private func rejection(_ expected: NativeKeyFailure, _ operation: () throws -> Void) throws {
        do { try operation() }
        catch let error as NativeKeyFailure {
            guard error == expected else { throw NativeKeyFailure.invalidResponse }
            return
        }
        throw QualificationFailure.unexpectedSuccess
    }
    private func directory() throws -> URL {
        let folder = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        return folder
    }
    private func write(_ value: [String: Any], to url: URL) throws {
        try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]).write(to: url, options: .atomic)
    }
    private func read(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        guard data.count <= 8192, let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw NativeKeyFailure.invalidResponse }
        return value
    }
    private func qualify(_ phase: String) throws -> [String: Any] {
        let stateURL = try directory().appendingPathComponent("encrypted-fixture.json")
        if phase == "rejection_helper" {
            do {
                try rejection(.invalidResponse) { }
                throw QualificationFailure.assertionFailed
            } catch QualificationFailure.unexpectedSuccess {
                return ["status": "pass", "phase": phase]
            }
        }
        if phase == "input" {
            try rejection(.invalidInput) { _ = try MobileKeyBridge(namespace: " ", currentVersion: "v1") }
            let bridge = try MobileKeyBridge(namespace: "qualification-input", currentVersion: "v1")
            try rejection(.invalidInput) { _ = try bridge.wrap(alias: "", dataKey: Data(repeating: 0, count: 32)) }
            try rejection(.invalidInput) { _ = try bridge.wrap(alias: "generated", dataKey: Data(repeating: 0, count: 31)) }
            try rejection(.invalidInput) { _ = try bridge.unwrap(alias: "generated", version: "v1", frame: Data()) }
            return ["status": "pass", "phase": phase]
        }
        if phase == "cleanup" {
            if FileManager.default.fileExists(atPath: stateURL.path) {
                let state = try read(stateURL); let namespace = try fixtureNamespace(state)
                let status = SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: "SunlitSDv1." + namespace, kSecAttrSynchronizable: false] as CFDictionary)
                guard status == errSecSuccess || status == errSecItemNotFound else { throw NativeKeyFailure.unavailable }
                try FileManager.default.removeItem(at: stateURL)
            }
            return ["status": "pass", "phase": phase]
        }
        if phase == "seed" {
            // Record cleanup ownership atomically before creating any key.
            let namespace = "qualification-" + UUID().uuidString
            try write(["namespace": namespace], to: stateURL)
            let bridge = try MobileKeyBridge(namespace: namespace, currentVersion: "v1")
            var key = Data(count: 32)
            guard key.withUnsafeMutableBytes({ SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }) == errSecSuccess else { throw NativeKeyFailure.unavailable }
            defer { key.resetBytes(in: 0..<key.count) }
            if !LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) {
                try rejection(.custodyRejected) { _ = try bridge.wrap(alias: "generated-key", dataKey: key) }
                return ["status": "blocked", "phase": phase, "kind": "PASSCODE_REQUIRED", "noFallback": true]
            }
            let wrapped = try bridge.wrap(alias: "generated-key", dataKey: key)
            guard !wrapped.hardwareBacked else { throw NativeKeyFailure.invalidResponse }
            try write(["namespace": namespace, "alias": wrapped.alias, "version": wrapped.version, "frame": wrapped.frame.base64EncodedString(), "digest": Data(SHA256.hash(data: key)).base64EncodedString()], to: stateURL)
            return ["status": "pass", "phase": phase, "reportedCustody": "softwareKeychainPasscodeOnly"]
        }
        let state = try read(stateURL); let namespace = try fixtureNamespace(state)
        guard let alias = state["alias"] as? String, let version = state["version"] as? String, let encoded = state["frame"] as? String, let frame = Data(base64Encoded: encoded) else { throw NativeKeyFailure.invalidResponse }
        let bridge = try MobileKeyBridge(namespace: namespace, currentVersion: "v1")
        if phase == "recover" {
            let unwrapped = try bridge.unwrap(alias: alias, version: version, frame: frame)
            defer { unwrapped.close() }
            let digest = try unwrapped.withBytes { buffer in
                var copy = Data(buffer)
                defer { copy.resetBytes(in: 0..<copy.count) }
                return Data(SHA256.hash(data: copy)).base64EncodedString()
            }
            guard digest == state["digest"] as? String, !unwrapped.hardwareBacked else { throw NativeKeyFailure.invalidResponse }
            unwrapped.close()
            try rejection(.invalidResponse) { _ = try unwrapped.withBytes { $0.count } }
        } else if phase == "tamper" {
            var changed = frame; changed[changed.count - 1] ^= 1
            try rejection(.authenticationFailed) { _ = try bridge.unwrap(alias: alias, version: version, frame: changed) }
            try rejection(.missing) { _ = try bridge.unwrap(alias: "wrong-alias", version: version, frame: frame) }
            try rejection(.missing) { _ = try bridge.unwrap(alias: alias, version: "wrong-version", frame: frame) }
        } else if phase == "invalidate" {
            let status = SecItemDelete([kSecClass: kSecClassGenericPassword, kSecAttrService: "SunlitSDv1." + namespace, kSecAttrSynchronizable: false] as CFDictionary)
            guard status == errSecSuccess else { throw NativeKeyFailure.unavailable }
        } else if phase == "recover_deleted" {
            try rejection(.missing) { _ = try bridge.unwrap(alias: alias, version: version, frame: frame) }
        } else { throw NativeKeyFailure.invalidInput }
        return ["status": "pass", "phase": phase]
    }
    private func fixtureNamespace(_ state: [String: Any]) throws -> String {
        guard let value = state["namespace"] as? String, value.hasPrefix("qualification-"), UUID(uuidString: String(value.dropFirst("qualification-".count))) != nil else { throw NativeKeyFailure.invalidResponse }
        return value
    }
    private func runQualification() {
        let args = ProcessInfo.processInfo.arguments
        let phase = args.firstIndex(of: "--phase").flatMap { $0 + 1 < args.count ? args[$0 + 1] : nil } ?? "input"
        var report: [String: Any]
        do { report = try qualify(phase) }
        catch let failure as NativeKeyFailure { report = ["status": "fail", "phase": phase, "kind": String(describing: failure)] }
        catch { report = ["status": "fail", "phase": phase, "kind": "QUALIFICATION_ASSERTION"] }
        do { try write(report, to: directory().appendingPathComponent("qualification-result.json")) } catch { }
    }
}
