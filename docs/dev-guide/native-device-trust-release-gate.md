# Native Device Trust Release Gate

SunLitSecurityLibraries is the producer of the native device-trust APIs.
ZeroTrustAuth is the conformance consumer that proves those APIs in an external
client/server flow before Sunlit Guardian relies on them.

## Gate Shape

1. Run the library contract tests:
   - `cargo test -p sunlit_secure_authz --test e2e_sunlit_ndt_m4 --all-features`
   - `cargo test -p sunlit_secure_identity -p sunlit_secure_authz -p sunlit_secure_network --all-features`
2. Call the reusable ZeroTrustAuth workflow:
   - `kerberosmansour/ZeroTrustAuth/.github/workflows/zero-trust-auth-external.yml@5a24e4115074f30e2372835fea30806a897704c3`
   - pass `ci_bootstrap_issuer_url`, `enrollment_url`, and `api_url` for real
     staging runs
3. Upload the ZeroTrustAuth conformance evidence artifact with the release.

The workflow is defined in
`.github/workflows/native-device-trust-conformance.yml`.

## External Boundary

The external endpoint remains test/staging only:

```text
GitHub Actions
  -> GitHub OIDC
  -> CI bootstrap issuer
  -> public mTLS endpoint
  -> CDN / Cloudflare-like edge
  -> AWS origin
  -> EKS Istio ingress
  -> Actix Web ZeroTrustAuth services
```

No production client private key belongs in GitHub secrets. The CI bootstrap
issuer must validate the GitHub OIDC token and return short-lived CI-scoped
bootstrap material that can only enroll test session certificates.

## Guardian Handoff

Sunlit Guardian should treat the uploaded external conformance artifact as a
release-blocking dependency once it consumes the native device-trust libraries.
The expected sequence remains:

1. session mTLS/device trust;
2. optional platform attestation according to backend mode;
3. passwordless user login;
4. `secure_authz::DeviceTrustContext` route authorization.
