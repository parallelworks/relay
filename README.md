# relay

An authenticated TCP relay built only on published standards. A client opens an HTTP `CONNECT` tunnel with a DPoP-bound OAuth access token. The relay asks the authorization server, by token introspection, whether the token is active and which single address it may reach, dials that address, and copies bytes until either side closes or the authorization server revokes the session.

The relay makes no access decisions of its own. Put it inside a private network to give authorized clients a path to hosts there, without opening those hosts to the internet and without routing their traffic through a central service.

- **Protocol**: [SPEC.md](SPEC.md)
- **Threat model**: [THREAT_MODEL.md](THREAT_MODEL.md)
- **Security policy**: [SECURITY.md](SECURITY.md)

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

## Running

```sh
GOFIPS140=certified CGO_ENABLED=0 go build -trimpath ./cmd/relay
./relay -config /etc/relay/config.json
```

`relay -version` prints the version and the FIPS 140-3 module it runs. The configuration is JSON; unknown members are errors.

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
| `registration` | Directory for the relay's key and `client_id`, and the file holding a single-use initial access token for the first start. |
| `egress` | Prefixes the relay may dial, and special-purpose addresses inside them that it may dial anyway (SPEC.md, Egress policy). |
| `dpop_nonces` | Present to require DPoP nonces. `lifetime` (default `5m`) and `key_file`, a key of at least 32 bytes shared by every replica. |
| `session` | Re-introspection `interval` and `grace`. |
| `limits` | `max_tunnels`, `max_tunnels_per_source`, `max_conns_per_source`, `failed_auth_per_minute`, `dial_timeout`, `introspection_timeout`, `read_header_timeout`, `idle_timeout`, `max_tunnel_lifetime` (default `24h`). |
| `shutdown_timeout` | How long `SIGTERM` waits for open tunnels before closing them. Default `30s`. |
| `log_level` | `DEBUG`, `INFO`, `WARN` or `ERROR`. Logs are JSON on standard error. |

## Conformance

[`conformance`](conformance) checks an authorization server and a relay from the outside, over HTTP/1.1 and HTTP/2. To check an authorization server, implement `conformance.Environment` with tokens it issues to a running relay and call `conformance.Run` from a Go test.

## Development

```sh
go test -race -shuffle=on ./...
(cd integration && go test -race ./...)
GOFIPS140=certified GODEBUG=fips140=only go test ./...
```

The integration test builds the relay, registers it with an in-memory authorization server, and runs an SSH session and a 1 GiB `sftp` upload through it, revokes a session mid-transfer and rotates the certificate mid-run.

## Status

Pre-release. The protocol is at version 1; the code is under construction.

## License

[Apache License 2.0](LICENSE)
