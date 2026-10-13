# Relay protocol, version 1

This document is the contract between a relay, its clients, and the OAuth 2.0 authorization server that decides what each client may reach. It uses only published standards plus the two introspection members defined in [Introspection members](#introspection-members). Member names, error codes and defaults in this document never change meaning within version 1.

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## Roles

- **Client**: opens a tunnel through the relay. It holds a DPoP-bound access token issued for one tunnel and the private key the token is bound to.
- **Relay**: a confidential OAuth client of the authorization server and a resource server for tunnel requests. It authorizes nothing itself: every decision comes from token introspection.
- **Authorization server (AS)**: issues the client's token, answers introspection, and registers relays.
- **Target**: the TCP endpoint the AS names for a token.

## Overview

1. The client obtains an access token from the AS by any grant the AS supports. The token is bound to a DPoP key (RFC 9449) and its introspection carries a `relay_target` and a `relay_session`.
2. The client connects to the relay over TLS and sends `CONNECT` for the target, presenting the token and a DPoP proof.
3. The relay introspects the token (RFC 7662), checks the response and the proof, checks the target against its egress policy, dials the target, and answers `200`.
4. From then on the relay copies bytes in both directions without interpreting them.
5. While the tunnel is open the relay re-introspects `relay_session` on an interval and closes the tunnel when it is no longer active.

## Transport

- The relay MUST accept TLS 1.3 (RFC 8446) only, and MUST offer the ALPN protocols `http/1.1` and `h2`.
- Cipher suites and key exchange groups are those permitted by the FIPS 140-3 validated module the relay is built with.
- The relay MUST NOT accept cleartext HTTP.

## Tunnel request

### HTTP/1.1

The client sends a `CONNECT` request (RFC 9110 §9.3.6, RFC 9112 §3.2.3) whose request-target is the target in authority-form:

```
CONNECT 10.4.2.17:41823 HTTP/1.1
Host: 10.4.2.17:41823
Authorization: DPoP <access token>
DPoP: <DPoP proof JWT>
```

After a `2xx` response, the TLS connection carries the tunnel. A response with any other status ends the exchange and the relay closes the connection.

### HTTP/2

The client sends a `CONNECT` request (RFC 9113 §8.5) with `:method` = `CONNECT` and `:authority` = the target, and no `:scheme` or `:path`. The `Authorization` and `DPoP` fields are the same as for HTTP/1.1. After a `2xx` response, the stream carries the tunnel. The extended CONNECT protocol (RFC 8441) is not used, and a request with a `:protocol` pseudo-header is rejected.

When the target ends its stream, the relay ends the HTTP/2 stream (`END_STREAM`) after the pending bytes and stops reading from the client (RFC 9113 §8.1 allows the `RST_STREAM` with `NO_ERROR` that may follow). When the client ends its stream, the relay half-closes the target connection and keeps relaying the target's bytes.

### Target

- The request authority MUST be an IP literal and a port (`192.0.2.10:22`, `[2001:db8::10]:22`). Host names MUST be rejected, so no DNS resolution ever happens on the relay.
- After introspection the relay MUST require the request authority to equal `relay_target` exactly, after both are parsed into an address and port. The token, not the request, selects the destination; the request authority only lets the client and intermediaries see where the tunnel goes.

### Target URI

The target URI of a tunnel request, used as the DPoP `htu`, is `https://` followed by the request authority (RFC 9112 §3.3 for authority-form, RFC 9113 §8.5 for HTTP/2). For the example above it is `https://10.4.2.17:41823`.

## Token presentation

The client presents the token with the `DPoP` authentication scheme (RFC 9449 §7.1):

- `Authorization: DPoP <access token>`
- `DPoP: <proof>`, a JWT as described in RFC 9449 §4.2 with:
  - `typ` = `dpop+jwt`
  - `alg` one of `ES256`, `ES384`, `PS256`
  - `jwk` the public key
  - `jti` a unique identifier
  - `htm` = `CONNECT`
  - `htu` = the target URI
  - `iat` the current time
  - `ath` = base64url(SHA-256(access token))
  - `nonce` when the relay has required one

The relay MUST reject the `Bearer` scheme, more than one `Authorization` field, more than one `DPoP` field, and a token or proof in any other location.

### Proof verification

The relay MUST perform the checks of RFC 9449 §4.3, specifically:

1. Exactly one `DPoP` field, and it is a well-formed compact JWS.
2. `typ` is `dpop+jwt`.
3. `alg` is on the relay's allowlist and is not `none` or a MAC algorithm.
4. `jwk` is a public key of a type matching `alg` and contains no private members.
5. The signature verifies with `jwk`.
6. `htm` equals the request method.
7. `htu` equals the target URI after normalization (RFC 3986 §6.2.2 and §6.2.3).
8. `iat` is within the acceptance window (default ±60 seconds).
9. `jti` has not been seen within the acceptance window.
10. `ath` equals base64url(SHA-256(access token)).
11. When the relay requires nonces, `nonce` equals a nonce the relay issued and has not expired.
12. The JWK SHA-256 thumbprint (RFC 7638) of `jwk` equals the token's `cnf.jkt` (RFC 9449 §6.1).

### Nonces

A relay MAY require server-provided nonces (RFC 9449 §9). It then answers a request without a valid nonce with `401`, `WWW-Authenticate: DPoP error="use_dpop_nonce"`, and a `DPoP-Nonce` field. Nonces are opaque to the client.

## Introspection

The relay introspects the access token at the AS's introspection endpoint (RFC 7662 §2.1):

```
POST /introspect HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Accept: application/json

token=<access token>&token_type_hint=access_token
&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer
&client_assertion=<JWT>
```

### Relay authentication

The relay authenticates with `private_key_jwt` (RFC 7523 §2.2, OpenID Connect Core §9). The assertion is a JWS with:
- `iss` and `sub`: the relay's `client_id`
- `aud`: the AS's issuer identifier (RFC 8414)
- `exp`: no more than 60 seconds after `iat`
- `iat`
- `jti`: unique per assertion

It is signed with the relay's registered key using `ES256`, `ES384` or `PS256`.

### Endpoint discovery

The relay discovers `introspection_endpoint` and `registration_endpoint` from the AS's metadata at `/.well-known/oauth-authorization-server` (RFC 8414). The metadata `issuer` MUST equal the configured issuer. Endpoints MUST use `https`.

### Response validation

The relay MUST treat the token as invalid unless all of the following hold:

1. The response status is `200` and its media type is `application/json`.
2. The body is at most 64 KiB and is a single JSON object.
3. `active` is `true`.
4. `token_type`, when present, is `DPoP`.
5. `aud` is present and contains the relay's identifier.
6. `exp` is present and in the future.
7. `cnf.jkt` is present.
8. `relay_target` and `relay_session` are present and valid as defined below.

Members the relay does not know are ignored (RFC 7662 §2.2).

### Introspection members

| Member | Type | Meaning |
|---|---|---|
| `relay_target` | string | The only destination this token may reach, as an IP literal and port in the same form as a request authority. |
| `relay_session` | string | An opaque token, at most 512 bytes, that the relay introspects while the tunnel is open. The AS MUST return it only for tokens it would also issue to a relay, and MUST make it unusable for anything but introspection by this relay. |

The relay identifier is the relay's `client_id`. An AS issuing tokens for a relay MUST put that `client_id` in the token's audience.

### Single use

An AS SHOULD treat a tunnel access token as single use: it SHOULD answer `active: false` to every introspection after the first. A relay MUST NOT cache introspection responses for access tokens.

## Session re-introspection

While a tunnel is open, the relay introspects its `relay_session` every `reintrospect_interval` (default 60 seconds), with the same client authentication and no `token_type_hint`. The relay MUST close the tunnel when:

- the response is valid and `active` is `false`;
- the response's `sub` differs from the `sub` of the access token's introspection;
- the response's `exp`, when present, has passed;
- no valid response has been received for `reintrospect_grace` (default 120 seconds). The relay fails closed.

Closing sends a TLS `close_notify` to the client over HTTP/1.1, or resets the HTTP/2 stream with `RST_STREAM`, and closes the target connection.

## Egress policy

The relay dials only addresses inside the configured prefixes. These addresses are refused even when a configured prefix contains them, unless the exact address is listed separately:

- loopback (`127.0.0.0/8`, `::1/128`)
- link-local (`169.254.0.0/16`, `fe80::/10`), which includes instance metadata services
- multicast (`224.0.0.0/4`, `ff00::/8`)
- unspecified (`0.0.0.0/32`, `::/128`)
- broadcast (`255.255.255.255/32`)
- IPv4-mapped IPv6 addresses, which are evaluated as their IPv4 address

The relay re-checks the address of the socket as it connects, so the check and the dial cannot disagree.

## Registration

A relay without credentials registers once, using Dynamic Client Registration (RFC 7591) with an initial access token supplied by its operator:

```
POST /register HTTP/1.1
Authorization: Bearer <initial access token>
Content-Type: application/json

{
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "ES256",
  "jwks": {"keys": [<public JWK>]},
  "grant_types": [],
  "response_types": [],
  "client_name": "<operator-chosen name>",
  "software_id": "github.com/parallelworks/relay",
  "software_version": "<version>"
}
```

The relay generates its key pair locally, sends only the public key, and stores the private key and returned `client_id`. The AS SHOULD treat the initial access token as single use.

## Errors

Every error response before the tunnel opens has a Problem Details body (RFC 9457, `application/problem+json`) whose `type` is `about:blank` and whose `title` is the status's reason phrase. Bodies never include the reason a token or proof was rejected; the relay logs it.

| Status | When | Additional fields |
|---|---|---|
| `400` | Malformed request: not `CONNECT`, bad authority, duplicate authorization fields | |
| `401` | Missing, malformed, inactive or mismatched token or proof | `WWW-Authenticate: DPoP error="invalid_token"` or `error="invalid_dpop_proof"`, with `algs="ES256 ES384 PS256"` (RFC 9449 §7.1) |
| `401` | Nonce required | `WWW-Authenticate: DPoP error="use_dpop_nonce"`, `DPoP-Nonce` |
| `403` | Token valid but the request authority differs from `relay_target`, or the target is outside the egress policy | |
| `429` | Rate limit on failed authentication, or too many concurrent tunnels from one source | `Retry-After` |
| `502` | The target refused or did not answer | |
| `503` | The relay is at its tunnel limit, is shutting down, or cannot reach the AS | `Retry-After` |

Over HTTP/1.1 every error response carries `Connection: close`. A source is an IPv4 address or an IPv6 /64. The relay closes connections from a source that already holds its share of connections before the TLS handshake, without a response.

## Observability (informative)

Relays emit OpenTelemetry signals. A conforming relay emits at least:

| Signal | Name | Attributes |
|---|---|---|
| Counter | `relay.tunnels` | `outcome` |
| UpDownCounter | `relay.tunnels.active` | |
| Counter | `relay.tunnel.bytes` | `direction` (`upstream`, `downstream`) |
| Histogram | `relay.tunnel.duration` | `close_reason` |
| Counter | `relay.auth.failures` | `reason` |
| Log record | `tunnel.closed` | `sub`, `target`, `bytes.upstream`, `bytes.downstream`, `duration`, `close_reason` |

Tokens never appear in any signal. A token is identified, where needed, by the first 8 hexadecimal characters of its SHA-256.

## Versioning

This is version 1. A change that alters the meaning of an existing member, error or default is a new version; adding an optional member is not.
