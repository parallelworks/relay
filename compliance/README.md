# NIST SP 800-53 Rev 5

<!-- Generated from component-definition.json by go run ./internal/cmd/compliance -write. Edit the JSON, not this file. -->

FedRAMP High, like any NIST SP 800-53 baseline, is a property of an authorized system, not of a component. This directory describes how the relay helps a system meet those controls.

[`component-definition.json`](component-definition.json) is an [OSCAL](https://pages.nist.gov/OSCAL/) 1.1.3 component definition that a system owner can import into a system security plan. Each control below says what the relay does, what the system owner is responsible for, and what proves it: tests by name, and [threat model](../THREAT_MODEL.md) mitigations, each of which names its own test.

`go run ./internal/cmd/compliance` fails when a named test, mitigation or file does not exist, or when this file is out of date. CI also validates the definition against the OSCAL schema and every control against the NIST SP 800-53 Rev 5 catalog.

| Control | Title |
|---|---|
| [AC-3](#ac-3-access-enforcement) | Access Enforcement |
| [AC-4](#ac-4-information-flow-enforcement) | Information Flow Enforcement |
| [AC-7](#ac-7-unsuccessful-logon-attempts) | Unsuccessful Logon Attempts |
| [AC-12](#ac-12-session-termination) | Session Termination |
| [AC-17](#ac-17-remote-access) | Remote Access |
| [AU-2](#au-2-event-logging) | Event Logging |
| [AU-3](#au-3-content-of-audit-records) | Content of Audit Records |
| [AU-8](#au-8-time-stamps) | Time Stamps |
| [AU-12](#au-12-audit-record-generation) | Audit Record Generation |
| [CM-6](#cm-6-configuration-settings) | Configuration Settings |
| [CM-7](#cm-7-least-functionality) | Least Functionality |
| [IA-5](#ia-5-authenticator-management) | Authenticator Management |
| [IA-9](#ia-9-service-identification-and-authentication) | Service Identification and Authentication |
| [IA-11](#ia-11-re-authentication) | Re-authentication |
| [RA-5](#ra-5-vulnerability-monitoring-and-scanning) | Vulnerability Monitoring and Scanning |
| [SA-11](#sa-11-developer-testing-and-evaluation) | Developer Testing and Evaluation |
| [SC-5](#sc-5-denial-of-service-protection) | Denial-of-service Protection |
| [SC-7](#sc-7-boundary-protection) | Boundary Protection |
| [SC-8](#sc-8-transmission-confidentiality-and-integrity) | Transmission Confidentiality and Integrity |
| [SC-10](#sc-10-network-disconnect) | Network Disconnect |
| [SC-12](#sc-12-cryptographic-key-establishment-and-management) | Cryptographic Key Establishment and Management |
| [SC-13](#sc-13-cryptographic-protection) | Cryptographic Protection |
| [SC-23](#sc-23-session-authenticity) | Session Authenticity |
| [SI-10](#si-10-information-input-validation) | Information Input Validation |
| [SI-11](#si-11-error-handling) | Error Handling |
| [SR-3](#sr-3-supply-chain-controls-and-processes) | Supply Chain Controls and Processes |
| [SR-4](#sr-4-provenance) | Provenance |
| [SR-11](#sr-11-component-authenticity) | Component Authenticity |

## AC-3 Access Enforcement

The relay opens a tunnel only for an access token that the authorization server reports active (RFC 7662), that is bound to the client's key (RFC 9449), that names this relay in its audience, and whose relay_target equals the requested address. The authorization server makes each access decision; the relay enforces it on every request and asks again for every tunnel, never caching an answer.

**Shared responsibility:** The system owner defines who may reach which target in the authorization server and issues tunnel tokens accordingly.

**Tests:** `server.TestRejectsMissingCredentialsBeforeIntrospection`

**Mitigations:** M-16, M-17, M-18, M-20, M-24, M-29

**Code:** [`server/handler.go`](../server/handler.go), [`introspect/introspect.go`](../introspect/introspect.go)

## AC-4 Information Flow Enforcement

Egress is limited to the configured IP prefixes. Loopback, link-local, cloud metadata, multicast, unspecified and broadcast addresses are always denied, even inside an allowed prefix. Targets are IP literals, so no name resolution can change where a tunnel goes, and the dialer checks the address again at connect time.

**Shared responsibility:** The system owner lists the smallest prefixes that remote access needs in egress.allow.

**Tests:** `server.TestRejectsTargetsOutsideEgressPolicy`

**Mitigations:** M-30, M-31, M-32, M-33, M-34, M-54

**Code:** [`policy/policy.go`](../policy/policy.go)

## AC-7 Unsuccessful Logon Attempts

Each source (an IPv4 address or IPv6 /64) may fail authentication a limited number of times per minute, 30 by default. Further requests get 429 with Retry-After before any token is checked.

**Shared responsibility:** The system owner sets account lockout for user authentication at the authorization server.

**Tests:** `server.TestNonceChallengeDoesNotCountAsFailure`

**Mitigations:** M-39

**Code:** [`server/limits.go`](../server/limits.go)

## AC-12 Session Termination

The relay re-introspects every open tunnel's session every 60 seconds by default and closes the tunnel when the session is inactive, belongs to another subject, or has expired. When the authorization server gives no valid answer for the grace period, 120 seconds by default, the tunnel closes. Tunnels also close after an idle timeout and a maximum lifetime.

**Shared responsibility:** The system owner ends sessions at the authorization server, which the relay applies within one interval.

**Tests:** `session.TestClosesWhenSessionExpires`, `server.TestRevocationClosesTunnel`, `server.TestIdleTunnelCloses`, `server.TestTunnelLifetimeIsCapped`

**Mitigations:** M-40, M-41, M-42

**Code:** [`session/session.go`](../session/session.go), [`tunnel/tunnel.go`](../tunnel/tunnel.go)

## AC-17 Remote Access

The relay is a managed access control point for remote access to hosts in a private network. Every connection uses TLS 1.3, every tunnel is authorized for one target by a sender-constrained token, and every tunnel is recorded and monitored through logs and metrics.

**Shared responsibility:** The system owner routes remote access to the private network through the relay, authorizes each kind of remote access in the authorization server, and monitors the relay's records.

**Tests:** `conformance.TestConformance`

**Mitigations:** M-02, M-29, M-49, M-55

**Code:** [`server/server.go`](../server/server.go), [`server/handler.go`](../server/handler.go)

## AU-2 Event Logging

The relay logs these events: tunnel opened, tunnel closed with its reason, tunnel refused with its reason, connection refused at the per-source limit, certificate reloaded or failed to reload, relay started, stopping and shutdown timeout, and a recovered panic.

**Shared responsibility:** The system owner chooses which of these events to retain and coordinates them with the authorization server's logs.

**Mitigations:** M-55

**Code:** [`server/handler.go`](../server/handler.go), [`server/problem.go`](../server/problem.go), [`server/limits.go`](../server/limits.go), [`server/certs.go`](../server/certs.go), [`cmd/relay/main.go`](../cmd/relay/main.go)

## AU-3 Content of Audit Records

Tunnel records carry the time, the event, the source address and port, the subject, the authorization server's session, the first 8 hexadecimal digits of the token's SHA-256, the target, the protocol, and the outcome: bytes in each direction, duration and close reason, or the status and reason of a refusal.

**Shared responsibility:** The system owner correlates token_id and session with the authorization server's records to identify the person.

**Tests:** `server.TestAuditRecords`

**Mitigations:** M-55, M-43

**Code:** [`server/server.go`](../server/server.go), [`server/handler.go`](../server/handler.go), [`server/problem.go`](../server/problem.go)

## AU-8 Time Stamps

Each record carries an RFC 3339 timestamp with time zone, taken from the system clock.

**Shared responsibility:** The system owner synchronizes the host clock with an authoritative time source.

**Tests:** `server.TestAuditRecords`

**Code:** [`telemetry/redact.go`](../telemetry/redact.go)

## AU-12 Audit Record Generation

Every relay instance writes its records as JSON lines on standard error, through a handler that removes token-shaped values, and exports tunnel and authentication metrics over OTLP when an endpoint is configured.

**Shared responsibility:** The system owner collects standard error from every instance into the audit system and protects it there.

**Tests:** `server.TestAuditRecords`, `telemetry.TestObserverRecordsTheSpecSignals`

**Mitigations:** M-43

**Code:** [`telemetry/redact.go`](../telemetry/redact.go), [`telemetry/telemetry.go`](../telemetry/telemetry.go)

## CM-6 Configuration Settings

Configuration is one JSON file, decoded strictly: unknown members, trailing data and invalid values are errors, and the relay does not start. Defaults are the secure settings documented in the README.

**Shared responsibility:** The system owner keeps the configuration under change control, for example in the Helm values.

**Tests:** `cmd/relay.TestDecodeConfigRejects`, `cmd/relay.FuzzDecodeConfig`

**Code:** [`cmd/relay/config.go`](../cmd/relay/config.go)

## CM-7 Least Functionality

The relay does one thing: it serves HTTP CONNECT to IP targets. It refuses every other method, extended CONNECT and WebSocket, has no administrative interface, and ships as a static binary in a distroless image without a shell, running as a non-root user with every capability dropped and a read-only root filesystem.

**Shared responsibility:** The system owner deploys the image as published, or the chart, without adding capabilities.

**Tests:** `server.TestRejectsExtendedConnect`, `server.TestRejectsMalformedRequests`

**Mitigations:** M-53, M-52

**Code:** [`server/handler.go`](../server/handler.go), [`Dockerfile`](../Dockerfile), [`deploy/helm/relay/templates/deployment.yaml`](../deploy/helm/relay/templates/deployment.yaml)

## IA-5 Authenticator Management

Tunnel tokens are sender-constrained: a bearer token is refused, and each request carries a fresh DPoP proof signed by the key the token is bound to. The relay never stores a token. Its own registration key is generated in the FIPS module, written with mode 0600 (or 0640 when owned by root), refused when readable by others, read only from its directory, and never sent: registration carries only the public key.

**Shared responsibility:** The system owner sets token lifetimes at the authorization server and protects the Secret or directory that holds the relay's key.

**Mitigations:** M-02, M-13, M-43, M-45, M-46, M-47

**Code:** [`registration/registration.go`](../registration/registration.go), [`dpop/verify.go`](../dpop/verify.go)

## IA-9 Service Identification and Authentication

The relay authenticates to the authorization server with private_key_jwt (RFC 7523), using a key registered by RFC 7591 dynamic registration. It authenticates the server through TLS 1.3, requires the metadata's issuer to equal the configured issuer (RFC 8414), and refuses non-HTTPS endpoints.

**Shared responsibility:** The system owner configures the issuer URL and, for a private certificate authority, its root certificate.

**Mitigations:** M-25, M-26, M-27, M-28

**Code:** [`introspect/introspect.go`](../introspect/introspect.go), [`registration/registration.go`](../registration/registration.go)

## IA-11 Re-authentication

Each tunnel's session is re-checked with the authorization server every interval; a tunnel cannot outlive its session.

**Shared responsibility:** The system owner sets session lifetimes and re-authentication requirements at the authorization server.

**Mitigations:** M-40, M-42

**Code:** [`session/session.go`](../session/session.go)

## RA-5 Vulnerability Monitoring and Scanning

Every change runs govulncheck on the source and on the built binary, CodeQL, and Trivy and Grype scans of the image that fail on high or critical findings with a fix. govulncheck also runs nightly against the latest database.

**Shared responsibility:** The system owner scans deployed images on their own schedule and applies relay releases.

**Code:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.github/workflows/codeql.yml`](../.github/workflows/codeql.yml), [`.github/workflows/nightly.yml`](../.github/workflows/nightly.yml)

## SA-11 Developer Testing and Evaluation

Every change runs the race detector with shuffled test order on Linux, macOS and Windows, a coverage floor of 90% per package and 100% of verification branches in dpop and policy, fuzzing of every parser, an integration test with a real SSH session, and a test for every threat model mitigation. Mutation testing and long fuzzing run nightly.

**Tests:** `internal/cmd/mitigations.TestRepositoryThreatModel`

**Code:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.github/workflows/nightly.yml`](../.github/workflows/nightly.yml), [`THREAT_MODEL.md`](../THREAT_MODEL.md)

## SC-5 Denial-of-service Protection

The relay bounds header read time and size, connections per source, tunnels per source and in total, tracked sources, failed authentications per source, introspection response size and time, the DPoP replay cache, and each tunnel's idle time and lifetime. A source over its connection share is closed before the TLS handshake.

**Shared responsibility:** The system owner sizes the limits for expected load and provides network-level protection in front of the relay.

**Tests:** `server.TestReplayCacheFull`, `server.TestIntrospectionTimeout`

**Mitigations:** M-22, M-35, M-36, M-37, M-38, M-39

**Code:** [`server/limits.go`](../server/limits.go), [`server/server.go`](../server/server.go)

## SC-7 Boundary Protection

The relay is the managed interface between untrusted clients and the private network: it accepts only authorized tunnels to allowed prefixes and denies special-purpose addresses. The chart's NetworkPolicy admits only the relay port and allows egress only to the authorization server, the allowed prefixes and DNS.

**Shared responsibility:** The system owner places the relay at the boundary of the private network and keeps other paths into it closed.

**Mitigations:** M-31, M-32, M-54

**Code:** [`policy/policy.go`](../policy/policy.go), [`deploy/helm/relay/templates/networkpolicy.yaml`](../deploy/helm/relay/templates/networkpolicy.yaml)

## SC-8 Transmission Confidentiality and Integrity

Clients reach the relay over TLS 1.3 only, and the relay reaches the authorization server over TLS 1.3 only; earlier versions are refused. Tunnel payloads are additionally protected end to end by the application, for example SSH.

**Shared responsibility:** The system owner provides the relay's certificate and uses end-to-end encrypted protocols inside tunnels.

**Mitigations:** M-26, M-27, M-49

**Code:** [`server/server.go`](../server/server.go), [`introspect/introspect.go`](../introspect/introspect.go)

## SC-10 Network Disconnect

A tunnel with no traffic in either direction closes after the idle timeout, one hour by default, and every tunnel closes at its maximum lifetime, 24 hours by default.

**Shared responsibility:** The system owner sets idle and lifetime limits that match organizational policy.

**Tests:** `server.TestIdleTunnelCloses`, `server.TestTunnelLifetimeIsCapped`, `tunnel.TestPipeIdleTimeout`, `tunnel.TestPipeMaxLifetime`

**Code:** [`tunnel/tunnel.go`](../tunnel/tunnel.go)

## SC-12 Cryptographic Key Establishment and Management

The relay generates its registration key in the FIPS module and stores it with restrictive permissions under a directory it reads through os.Root. TLS certificates are read the same way and reload without a restart.

**Shared responsibility:** The system owner issues and rotates the relay's TLS certificate and, when needed, re-registers the relay to rotate its key.

**Mitigations:** M-45, M-47, M-50

**Code:** [`registration/registration.go`](../registration/registration.go), [`server/certs.go`](../server/certs.go)

## SC-13 Cryptographic Protection

All cryptography uses the Go Cryptographic Module v1.0.0, FIPS 140-3 certificate #5247. Release binaries are built with GOFIPS140=certified and run with fips140=only, so any non-approved algorithm fails. DPoP and client assertions use ES256, ES384 or PS256 only.

**Shared responsibility:** The system owner runs the published release binaries or images, which record the module version in their build information.

**Mitigations:** M-05, M-51

**Code:** [`cmd/relay/main.go`](../cmd/relay/main.go), [`scripts/build.sh`](../scripts/build.sh), [`dpop/dpop.go`](../dpop/dpop.go)

## SC-23 Session Authenticity

Each request carries a DPoP proof bound to the method, the target, the token's hash and, when nonces are enabled, a relay-issued nonce. Proofs are single use and short lived, and the token must be bound to the proof's key, so a captured request cannot be replayed or redirected.

**Mitigations:** M-08, M-09, M-10, M-11, M-12, M-13, M-14, M-15

**Code:** [`dpop/verify.go`](../dpop/verify.go), [`dpop/nonce.go`](../dpop/nonce.go)

## SI-10 Information Input Validation

The relay validates every input against its specification and rejects anything else: the CONNECT request and its authority (IP literal and port), credential fields, DPoP proofs, introspection responses and their member types, server metadata, and its configuration. Every parser has a fuzz target.

**Tests:** `server.FuzzConnectRequest`, `dpop.FuzzVerify`, `policy.FuzzParseTarget`, `introspect.FuzzIntrospectionResponse`

**Mitigations:** M-03, M-04, M-23, M-30, M-36

**Code:** [`server/handler.go`](../server/handler.go), [`dpop/verify.go`](../dpop/verify.go), [`introspect/introspect.go`](../introspect/introspect.go), [`policy/policy.go`](../policy/policy.go)

## SI-11 Error Handling

Error responses are RFC 9457 problem details with only the status's title. Why a credential failed is logged, never returned.

**Mitigations:** M-44

**Code:** [`server/problem.go`](../server/problem.go)

## SR-3 Supply Chain Controls and Processes

Dependencies are limited to the standard library, go-jose and OpenTelemetry, and the client and dpop packages may import only the standard library and go-jose. CI pins every action by commit, grants each job the least permissions, restricts runner egress, checks workflows with zizmor and actionlint, verifies modules, and requires reproducible builds.

**Shared responsibility:** The system owner obtains the relay from its releases and verifies signatures and provenance before deployment.

**Mitigations:** M-52

**Code:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.golangci.yml`](../.golangci.yml), [`.github/dependabot.yml`](../.github/dependabot.yml)

## SR-4 Provenance

Each release carries SLSA Build Level 3 provenance from GitHub artifact attestations for the binaries, image and chart, and SPDX and CycloneDX SBOMs. Binaries record their module versions and the FIPS module version in their build information.

**Shared responsibility:** The system owner keeps the provenance and SBOMs with the system's inventory.

**Code:** [`.github/workflows/build.yml`](../.github/workflows/build.yml), [`.github/workflows/release.yml`](../.github/workflows/release.yml), [`scripts/build.sh`](../scripts/build.sh)

## SR-11 Component Authenticity

Release checksums, the image and the chart are signed with Sigstore keyless signatures tied to the release workflow.

**Shared responsibility:** The system owner verifies signatures or attestations, for example with gh attestation verify, before deployment.

**Code:** [`.github/workflows/build.yml`](../.github/workflows/build.yml)
