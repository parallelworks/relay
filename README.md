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

## Status

Pre-release. The protocol is at version 1; the code is under construction.

## License

[Apache License 2.0](LICENSE)
