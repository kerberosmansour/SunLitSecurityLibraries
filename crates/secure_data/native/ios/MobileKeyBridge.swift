import Foundation
import Security
import CryptoKit
import LocalAuthentication

public enum NativeKeyFailure: Error {
    case invalidInput, invalidResponse, custodyRejected, missing, locked
    case invalidated, unavailable, incomplete, authenticationFailed
}
public struct IosKeyCustody {
    public let deviceOnly = true
    public let synchronizable = false
    public let backupExcluded = true
    public let hardwareBacked = false
}
public struct NativeWrappedKey {
    public let alias: String
    public let version: String
    public let frame: Data
    public let custody: IosKeyCustody
    public var hardwareBacked: Bool { custody.hardwareBacked }
}
public final class NativeUnwrappedKey {
    public let alias: String
    public let version: String
    public let custody = IosKeyCustody()
    public var hardwareBacked: Bool { custody.hardwareBacked }
    private var bytes: Data
    init(alias: String, version: String, bytes: Data) {
        self.alias = alias; self.version = version; self.bytes = bytes
    }
    public func withBytes<T>(_ body: (UnsafeRawBufferPointer) throws -> T) throws -> T {
        guard bytes.count == 32 else { throw NativeKeyFailure.invalidResponse }
        return try bytes.withUnsafeBytes(body)
    }
    public func close() { bytes.resetBytes(in: 0..<bytes.count); bytes.removeAll() }
    deinit { close() }
}
public final class MobileKeyBridge {
    private static let operation = NSLock()
    private let namespace: String
    private let currentVersion: String
    public init(namespace: String, currentVersion: String) throws {
        guard Self.identifier(namespace, limit: 64), Self.identifier(currentVersion, limit: 64) else { throw NativeKeyFailure.invalidInput }
        self.namespace = namespace; self.currentVersion = currentVersion
    }
    private static func identifier(_ value: String, limit: Int) -> Bool {
        return !value.isEmpty && value.utf8.count <= limit && value.utf8.allSatisfy { (0x21...0x7e).contains($0) }
    }
    private func aad(alias: String, version: String) -> Data {
        var result = Data()
        for value in [alias, version] {
            var size = UInt32(value.utf8.count).bigEndian
            withUnsafeBytes(of: &size) { result.append(contentsOf: $0) }
            result.append(contentsOf: value.utf8)
        }
        return result
    }
    private func identity(alias: String, version: String) -> [CFString: Any] {
        return [kSecClass: kSecClassGenericPassword, kSecAttrService: "SunlitSDv1." + namespace,
                kSecAttrAccount: aad(alias: alias, version: version).base64EncodedString(), kSecAttrSynchronizable: false]
    }
    private func fixedFailure(_ status: OSStatus) -> NativeKeyFailure {
        switch status {
        case errSecItemNotFound: return .missing
        case errSecInteractionNotAllowed, errSecAuthFailed: return .locked
        case errSecDecode: return .invalidated
        default: return .unavailable
        }
    }
    private func readKey(alias: String, version: String) throws -> SymmetricKey {
        var query = identity(alias: alias, version: version)
        query[kSecReturnAttributes] = true; query[kSecReturnData] = true
        let authentication = LAContext(); authentication.interactionNotAllowed = true
        query[kSecMatchLimit] = kSecMatchLimitOne; query[kSecUseAuthenticationContext] = authentication
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw fixedFailure(status) }
        guard let record = result as? [String: Any], var bytes = record[kSecValueData as String] as? Data else { throw NativeKeyFailure.invalidResponse }
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard record[kSecAttrAccessible as String] as? String == kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly as String,
              (record[kSecAttrSynchronizable as String] as? Bool ?? false) == false else { throw NativeKeyFailure.custodyRejected }
        guard bytes.count == 32 else { throw NativeKeyFailure.invalidResponse }
        return SymmetricKey(data: bytes)
    }
    private func key(alias: String, version: String, create: Bool) throws -> SymmetricKey {
        do { return try readKey(alias: alias, version: version) }
        catch NativeKeyFailure.missing {
            guard create else { throw NativeKeyFailure.missing }
        }
        // This checks current prerequisites without displaying authentication UI.
        // The Keychain class itself remains the final passcode/unlock authority.
        guard LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil) else { throw NativeKeyFailure.custodyRejected }
        var bytes = Data(count: 32)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        let entropy = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
        guard entropy == errSecSuccess else { throw NativeKeyFailure.unavailable }
        var item = identity(alias: alias, version: version)
        item[kSecAttrAccessible] = kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
        item[kSecValueData] = bytes
        let status = SecItemAdd(item as CFDictionary, nil)
        // A duplicate/partial creation is a fixed failure, never overwrite/retry.
        guard status == errSecSuccess else { throw fixedFailure(status) }
        return try readKey(alias: alias, version: version)
    }
    private func deadline(_ started: UInt64) throws {
        guard DispatchTime.now().uptimeNanoseconds - started <= 2_000_000_000 else { throw NativeKeyFailure.unavailable }
    }
    public func wrap(alias: String, dataKey: Data) throws -> NativeWrappedKey {
        guard Self.identifier(alias, limit: 128), dataKey.count == 32 else { throw NativeKeyFailure.invalidInput }
        guard Self.operation.try() else { throw NativeKeyFailure.unavailable }
        defer { Self.operation.unlock() }
        let started = DispatchTime.now().uptimeNanoseconds
        do {
            let key = try key(alias: alias, version: currentVersion, create: true)
            // CryptoKit generates a fresh random nonce when omitted.
            let box = try AES.GCM.seal(dataKey, using: key, authenticating: aad(alias: alias, version: currentVersion))
            guard let combined = box.combined, combined.count == 60 else { throw NativeKeyFailure.invalidResponse }
            var frame = Data([1]); frame.append(combined)
            try deadline(started)
            return NativeWrappedKey(alias: alias, version: currentVersion, frame: frame, custody: IosKeyCustody())
        } catch let failure as NativeKeyFailure { throw failure }
        catch { throw NativeKeyFailure.unavailable }
    }
    public func unwrap(alias: String, version: String, frame: Data) throws -> NativeUnwrappedKey {
        guard Self.identifier(alias, limit: 128), Self.identifier(version, limit: 64), frame.count == 61, frame.first == 1 else { throw NativeKeyFailure.invalidInput }
        guard Self.operation.try() else { throw NativeKeyFailure.unavailable }
        defer { Self.operation.unlock() }
        let started = DispatchTime.now().uptimeNanoseconds
        do {
            let key = try key(alias: alias, version: version, create: false)
            let box = try AES.GCM.SealedBox(combined: frame.dropFirst())
            var bytes: Data
            do { bytes = try AES.GCM.open(box, using: key, authenticating: aad(alias: alias, version: version)) }
            catch { throw NativeKeyFailure.authenticationFailed }
            var transferred = false
            defer { if !transferred { bytes.resetBytes(in: 0..<bytes.count) } }
            guard bytes.count == 32 else { throw NativeKeyFailure.invalidResponse }
            try deadline(started)
            let result = NativeUnwrappedKey(alias: alias, version: version, bytes: bytes)
            transferred = true; return result
        } catch let failure as NativeKeyFailure { throw failure }
        catch { throw NativeKeyFailure.unavailable }
    }
}
