# Threat model

This model covers the relay process, its configuration, and its three network boundaries. It uses STRIDE per boundary. Every mitigation has a stable identifier and names the test that proves it; `go run ./internal/cmd/mitigations` fails when a listed test is missing from a package that exists.

## Assets

- Reachability of targets inside the private network the relay sits in.
- Confidentiality and integrity of tunnel bytes.
- The relay's registration private key.
- Access tokens and session tokens presented to or held by the relay.
- Audit records of who reached what.

## Trust boundaries

1. **Client → relay**: untrusted clients on the public network.
2. **Relay → authorization server**: a trusted party over a network the relay does not control.
3. **Relay → target**: the private network.
4. **Operator → relay**: configuration, key material, deployment.
5. **Supply chain**: source, dependencies, build, and release.

## Assumptions

- The authorization server is trusted to make access decisions and to keep tunnel tokens single use.
- Tunnel payloads are end-to-end protected by the application (for example SSH), so the relay never needs to read them. The relay protects them in transit to itself with TLS, not from itself.
- The platform scheduler, container runtime and kernel enforce the restrictions in the deployment manifests.

## Mitigations

| ID | Boundary | STRIDE | Threat | Mitigation | Test |
|---|---|---|---|---|---|
| M-01 | 1 | S, D | A request with no credentials costs the relay an introspection or a dial | Requests without exactly one `Authorization: DPoP` and one `DPoP` field are rejected before any outbound call | `server.TestRejectsMissingCredentialsBeforeIntrospection` |
| M-02 | 1 | S | A stolen bearer token is replayed | Only the `DPoP` scheme is accepted | `server.TestRejectsBearerScheme` |
| M-03 | 1 | T | Ambiguous credentials through duplicated fields | Duplicate `Authorization` or `DPoP` fields are rejected | `server.TestRejectsDuplicateCredentialFields` |
| M-04 | 1 | S | A JWT of another type is used as a proof | `typ` must be `dpop+jwt` | `dpop.TestVerifyRejectsWrongType` |
| M-05 | 1 | S | Signature stripping or algorithm confusion | `alg` must be on the allowlist; `none` and MAC algorithms are refused | `dpop.TestVerifyRejectsDisallowedAlgorithm` |
| M-06 | 1 | I | A proof carries a private key | JWKs with private members are refused | `dpop.TestVerifyRejectsPrivateKey` |
| M-07 | 1 | S | A forged proof | The signature is verified with the embedded key | `dpop.TestVerifyRejectsBadSignature` |
| M-08 | 1 | S | A proof made for another method is replayed | `htm` must equal the request method | `dpop.TestVerifyRejectsMethodMismatch` |
| M-09 | 1 | S | A proof made for another target is replayed | `htu` must equal the normalized target URI | `dpop.TestVerifyRejectsURIMismatch` |
| M-10 | 1 | S | An old proof is replayed | `iat` must be inside the acceptance window | `dpop.TestVerifyRejectsStaleIssuedAt` |
| M-11 | 1 | S | A fresh proof is replayed | `jti` values are remembered for the acceptance window | `dpop.TestVerifyRejectsReplayedID` |
| M-12 | 1 | S | A proof is paired with a different token | `ath` must equal the token's hash | `dpop.TestVerifyRejectsTokenHashMismatch` |
| M-13 | 1 | S | A token is used with a key it is not bound to | The proof key's thumbprint must equal `cnf.jkt` | `dpop.TestVerifyRejectsThumbprintMismatch` |
| M-14 | 1 | S | Proofs are made ahead of time | Server nonces, when required, must be present, issued by this relay and unexpired | `dpop.TestVerifyRejectsMissingNonce` |
| M-15 | 1 | I | Timing reveals a valid nonce | Nonce MACs are compared in constant time | `dpop.TestSecretComparisonsUseConstantTime` |
| M-16 | 2 | S | A token is accepted from a stale answer | Introspection responses are never cached | `introspect.TestNeverCachesResponses` |
| M-17 | 2 | E | An inactive token is used | `active` must be `true` | `introspect.TestRejectsInactive` |
| M-18 | 2 | E | A token for another relay is used | `aud` must contain this relay's identifier | `introspect.TestRejectsWrongAudience` |
| M-19 | 2 | E | An expired token is used | `exp` must be present and in the future | `introspect.TestRejectsExpired` |
| M-20 | 2 | S | An unbound token is used | `cnf.jkt` must be present | `introspect.TestRejectsMissingConfirmation` |
| M-21 | 2 | E | A token of another type is used | `token_type`, when present, must be `DPoP` | `introspect.TestRejectsNonDPoPTokenType` |
| M-22 | 2 | D | A hostile or broken server exhausts memory | Response bodies are capped at 64 KiB | `introspect.TestRejectsOversizedResponse` |
| M-23 | 2 | T | Type confusion in a response | Members with the wrong JSON type invalidate the response | `introspect.TestRejectsWrongMemberTypes` |
| M-24 | 2 | E | A token without a destination is used | `relay_target` and `relay_session` must be present and valid | `introspect.TestRejectsMissingRelayMembers` |
| M-25 | 2 | S | Metadata from another issuer is trusted | Discovered `issuer` must equal the configured issuer | `introspect.TestDiscoveryRejectsIssuerMismatch` |
| M-26 | 2 | I | Endpoints are downgraded to cleartext | Discovered endpoints must be `https` | `introspect.TestDiscoveryRejectsNonHTTPSEndpoints` |
| M-27 | 2 | I | The connection to the server is intercepted | TLS 1.3 only, with the configured CA bundle when set | `introspect.TestRequiresTLS13` |
| M-28 | 2 | S | A client assertion is replayed elsewhere | The assertion's `aud` is the issuer, it lives at most 60 seconds, and its `jti` is unique | `introspect.TestClientAssertionClaims` |
| M-29 | 3 | E | The client picks a destination the token does not grant | The request authority must equal `relay_target` | `server.TestRejectsAuthorityTargetMismatch` |
| M-30 | 3 | E | DNS rebinding | Host names are refused; only IP literals are accepted | `policy.TestRejectsHostNames` |
| M-31 | 3 | E | A token names a destination outside the private network | The target must be inside a configured prefix | `policy.TestDeniesOutsidePrefixes` |
| M-32 | 3 | E | SSRF to loopback, link-local, metadata, multicast, unspecified or broadcast addresses | These are denied inside a configured prefix unless listed one by one | `policy.TestDeniesSpecialAddressesInsidePrefix` |
| M-33 | 3 | E | IPv4-mapped IPv6 bypasses IPv4 rules | Mapped addresses are evaluated as IPv4 | `policy.TestEvaluatesMappedAddressesAsIPv4` |
| M-34 | 3 | E | The dialed address differs from the checked one | The dialer's control hook re-checks the socket address | `policy.TestDialControlRechecksAddress` |
| M-35 | 1 | D | Slow headers hold connections open | `ReadHeaderTimeout` closes them | `server.TestReadHeaderTimeout` |
| M-36 | 1 | D | Oversized headers exhaust memory | Headers are capped at 8 KiB | `server.TestMaxHeaderBytes` |
| M-37 | 1 | D | One source holds every connection | Concurrent connections per source are capped | `server.TestPerSourceConnectionLimit` |
| M-38 | 1 | D | Many sources exhaust the relay | Total concurrent tunnels are capped with `503` | `server.TestTotalConnectionLimit` |
| M-39 | 1 | D, S | Credential guessing | Failed authentication is rate limited per source with `429` | `server.TestFailedAuthenticationRateLimit` |
| M-40 | 2 | E | Access outlives revocation | Session tokens are re-introspected; inactive sessions are closed | `session.TestClosesWhenSessionInactive` |
| M-41 | 2 | E | A session token is swapped for another user's | The session's `sub` must equal the access token's `sub` | `session.TestClosesOnSubjectMismatch` |
| M-42 | 2 | E | Revocation is evaded by cutting off the server | Sessions without a valid answer for the grace period are closed | `session.TestFailsClosedAfterGrace` |
| M-43 | 1, 2 | I | Tokens leak through logs or traces | The log handler redacts token-shaped values; tokens are identified by hash prefix only | `telemetry.TestRedactsTokens` |
| M-44 | 1 | I | Error bodies reveal why a credential failed | Bodies are generic Problem Details; the reason is only logged | `server.TestErrorBodiesOmitReason` |
| M-45 | 4 | I | The registration key is readable by others | The relay refuses a key file others may read: 0600 when owned by its user, at most 0640 when owned by root (a Secret mounted with an fsGroup), PostgreSQL's rule | `registration.TestRefusesPermissiveKeyFile` |
| M-46 | 4 | I | The private key leaves the relay | Registration sends only the public key | `registration.TestSendsOnlyPublicKey` |
| M-47 | 4 | T | Configuration files outside the configured directory are read | Files are opened through `os.Root` | `registration.TestKeyPathCannotEscapeRoot` |
| M-48 | 1 | D | A panic in one tunnel stops the relay | Panics close only the affected tunnel and are recorded | `tunnel.TestPanicClosesOnlyThatTunnel` |
| M-49 | 1 | I | A protocol downgrade exposes traffic | TLS 1.3 only | `server.TestRejectsTLS12` |
| M-50 | 4 | D | Certificate rotation requires downtime | Certificates reload on change without a restart | `server.TestReloadsCertificateWithoutRestart` |
| M-51 | 4, 5 | I, T | A non-approved algorithm is used | The binary runs with `GODEBUG=fips140=only` | `cmd/relay.TestRunsInFIPSOnlyMode` |
| M-52 | 5 | T | An unvetted dependency reaches client builds | `client` and `dpop` import only the standard library and go-jose | `internal/cmd/mitigations.TestClientDependencies` |
| M-53 | 4 | E | The container gains privileges | Non-root, read-only root, no capabilities, `RuntimeDefault` seccomp, restricted Pod Security | `deploy.TestChartPodSecurity` |
| M-54 | 3, 4 | E | The relay reaches more than it needs | The chart's NetworkPolicy allows egress only to the authorization server and the configured prefixes | `deploy.TestChartNetworkPolicy` |
| M-55 | 1 | R | A user denies reaching a target | Every opened, closed and refused tunnel is logged with its time, source, subject, session, token hash prefix, target and outcome | `server.TestAuditRecords` |

## Supply chain

Supply-chain threats are mitigated by CI rather than unit tests. Every gate is required on every pull request:

- Actions are pinned by commit SHA. Workflow permissions are least privilege. Runners are hardened with an egress allowlist.
- `zizmor` and `actionlint` check workflows.
- `go mod verify` and `govulncheck` run on source and binaries, with CodeQL, Trivy and Grype.
- Builds are reproducible, which CI checks by building on x86-64 and arm64 runners and comparing the binaries and the image digest.
- Releases carry SLSA Build Level 3 provenance, SBOMs and Sigstore signatures.
