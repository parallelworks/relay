# relay

An authenticated TCP relay built only on published standards. A client opens an HTTP `CONNECT` tunnel with a DPoP-bound OAuth access token. The relay asks the authorization server, by token introspection, whether the token is active and which single address it may reach, dials that address, and copies bytes until either side closes or the authorization server revokes the session.

The relay makes no access decisions of its own. Put it inside a private network to give authorized clients a path to hosts there, without opening those hosts to the internet and without routing their traffic through a central service.

- **Protocol**: [SPEC.md](SPEC.md)
- **Threat model**: [THREAT_MODEL.md](THREAT_MODEL.md)
- **Security policy**: [SECURITY.md](SECURITY.md)
- **NIST SP 800-53 controls**: [compliance](compliance)

## Standards

| Concern | Standard |
|---|---|
| Tunnel | HTTP `CONNECT`: RFC 9110 §9.3.6 over HTTP/1.1 (RFC 9112) and HTTP/2 (RFC 9113 §8.5) |
| Transport | TLS 1.3 (RFC 8446) |
| Proof of possession | DPoP (RFC 9449) |
| Authorization | OAuth 2.0 Token Introspection (RFC 7662) |
| Relay authentication | `private_key_jwt` (RFC 7523) |
| Discovery and registration | Authorization Server Metadata (RFC 8414), Dynamic Client Registration (RFC 7591) |
| Errors | Problem Details (RFC 9457) |
| Cryptography | FIPS 140-3: built with the Go Cryptographic Module (`GOFIPS140=certified`) and run with `GODEBUG=fips140=only` |
| Telemetry | OpenTelemetry |

## Installing

Each release publishes static binaries for Linux, macOS and Windows on x86-64 and arm64, a distroless image `ghcr.io/parallelworks/relay` for Linux on both architectures, and the Helm chart `oci://ghcr.io/parallelworks/charts/relay`. All are built with `GOFIPS140=certified`, signed, and carry SBOMs and SLSA Build Level 3 provenance; [SECURITY.md](SECURITY.md) shows how to verify them. To build from source:

```sh
GOFIPS140=certified CGO_ENABLED=0 go build -trimpath ./cmd/relay
```

`scripts/build.sh` builds every release binary the way releases do. Builds are reproducible: the same commit gives the same bytes on any host.

## Running

```sh
./relay -config /etc/relay/config.json
```

`relay -version` prints the version and the FIPS 140-3 module it runs. `relay -register` registers the relay with the authorization server if it has no registration yet, prints its `client_id`, and exits. The configuration is JSON; unknown members are errors.

```json
{
  "listen": ":8443",
  "issuer": "https://auth.example.com",
  "tls": {"dir": "/etc/relay/tls", "cert": "tls.crt", "key": "tls.key", "reload_interval": "1m"},
  "registration": {"dir": "/var/lib/relay", "initial_access_token_file": "/etc/relay/secrets/initial-access-token"},
  "egress": {"allow": ["10.0.0.0/8"], "exceptions": []},
  "session": {"interval": "60s", "grace": "120s"}
}
```

| Member | Meaning |
|---|---|
| `listen` | TCP address to accept TLS on. Default `:8443`. |
| `issuer` | The authorization server's issuer identifier. Its metadata is read from `/.well-known/oauth-authorization-server`. |
| `issuer_ca_file` | PEM roots for the authorization server's certificate. Default: the system roots. |
| `tls` | Directory, file names and reload interval of the relay's certificate and key. Changed files are served without a restart. |
| `registration` | Directory for the relay's key (`relay-key.pem`) and client (`relay-client.json`), and the file holding a single-use initial access token for the first start. The key must be owned by the relay's user with mode 0600, or by root with mode 0640, the rule PostgreSQL applies to its keys. |
| `egress` | Prefixes the relay may dial, and special-purpose addresses inside them that it may dial anyway (SPEC.md, Egress policy). |
| `dpop_nonces` | Present to require DPoP nonces. `lifetime` (default `5m`) and `key_file`, a key of at least 32 bytes shared by every replica. |
| `session` | Re-introspection `interval` and `grace`. |
| `limits` | `max_tunnels`, `max_tunnels_per_source`, `max_conns_per_source`, `failed_auth_per_minute`, `dial_timeout`, `introspection_timeout`, `read_header_timeout`, `idle_timeout`, `max_tunnel_lifetime` (default `24h`). |
| `shutdown_timeout` | How long `SIGTERM` waits for open tunnels before closing them. Default `30s`. |
| `log_level` | `DEBUG`, `INFO`, `WARN` or `ERROR`. Logs are JSON on standard error. |

The relay logs every opened, closed and refused tunnel with its source, subject, session, token hash prefix, target and outcome (SPEC.md, Observability). It removes anything shaped like a token, proof or credential from every record. Metrics are exported over OTLP/HTTP when `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_METRICS_ENDPOINT` is set, configured by the standard `OTEL_*` variables.

## Kubernetes

The chart runs the relay under the `restricted` Pod Security Standard with a read-only root filesystem and no capabilities, spreads replicas across nodes, and adds a PodDisruptionBudget and a NetworkPolicy that admits only the relay's port and allows egress only to the authorization server, the allowed prefixes and DNS. Replicas share one registration, made once before installing:

```sh
relay -register -config register.json   # registration.dir is a local directory
kubectl create namespace relay
kubectl label namespace relay pod-security.kubernetes.io/enforce=restricted
kubectl -n relay create secret generic relay-registration \
  --from-file=relay-key.pem --from-file=relay-client.json
kubectl -n relay create secret tls relay-tls --cert=tls.crt --key=tls.key
helm install relay oci://ghcr.io/parallelworks/charts/relay -n relay -f values.yaml
```

`values.yaml` sets at least `config.issuer`, `config.egress.allow`, `tls.secretName`, `registration.secretName` and `networkPolicy.authorizationServer`; [`values.yaml`](deploy/helm/relay/values.yaml) in the chart describes every setting. To require DPoP nonces with more than one replica, set `config.dpopNonces` and `nonceKey.secretName`, a Secret holding at least 32 random bytes that every replica shares.

## Client

[`client`](client) opens a tunnel and returns a `net.Conn`. It imports only the standard library and the JOSE library.

```go
conn, err := client.Dial(ctx, "https://relay.example.com:8443", "10.4.2.17:22", accessToken, dpopKey)
```

The access token and the address it grants come from the authorization server; `dpopKey` is the private key the token is bound to. A `client.Dialer` sets the TLS configuration and can send `CONNECT` over HTTP/2 instead of HTTP/1.1. A refusal is a `*client.Error` with the status, the DPoP error code and `Retry-After`.

## Benchmarks

[`bench`](bench) is a separate module. It compares `CONNECT` over HTTP/1.1 and HTTP/2 with a WebSocket tunnel: throughput through one and 64 tunnels, and the latency from dialing to the first relayed byte. CI runs it on the base branch and the change on the same runner. It fails when a result is significantly worse by more than 10%, or when `CONNECT` over HTTP/1.1 moves fewer bytes per second than the WebSocket tunnel. Significance uses benchstat's Mann-Whitney U test with Holm's correction across all comparisons, so noise alone fails a run at most 5% of the time. The WebSocket code lives only in that module, which never runs in FIPS 140-3 only mode: the WebSocket handshake needs SHA-1.

## Conformance

[`conformance`](conformance) checks an authorization server and a relay from the outside, over HTTP/1.1 and HTTP/2. To check an authorization server, implement `conformance.Environment` with tokens it issues to a running relay and call `conformance.Run` from a Go test.

## Development

```sh
go test -race -shuffle=on ./...
(cd integration && go test -race ./...)
(cd bench && go test -run '^$' -bench . ./...)
GOFIPS140=certified GODEBUG=fips140=only go test ./...
(cd deploy && go test ./...)           # renders the chart with helm
go run ./internal/cmd/mitigations -all # every threat model mitigation has its test
go run ./internal/cmd/compliance       # every control's evidence exists
```

The integration test builds the relay, registers it with an in-memory authorization server, and runs an SSH session and a 1 GiB `sftp` upload through it, revokes a session mid-transfer and rotates the certificate mid-run.

## Status

Pre-release: no version is tagged yet. The protocol is at version 1.

## License

[Apache License 2.0](LICENSE)
