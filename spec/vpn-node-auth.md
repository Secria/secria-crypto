# VPN API and server request signatures

Secria's VPN API and VPN servers talk over mutual TLS, with Ed25519
certificates from a private certificate authority and a hybrid X25519MLKEM768
key exchange. Each side also signs every request it sends with ML-DSA-65, as
this document specifies.

Encodings are defined in [README.md](README.md).

## 1. Keys

| Party | Key | Who holds the public key |
| --- | --- | --- |
| Each VPN server | Its own ML-DSA-65 key pair, made on the server | The VPN API, which pins it per server |
| The VPN API | One ML-DSA-65 key pair | Every VPN server, which pins it |

Keys use the FIPS 204 encodings: public keys of 1952 bytes, private keys of
4032 bytes. A verifier MUST refuse a pinned public key of any other length.

The VPN API MUST NOT accept a VPN server's public key from the server itself:
it pins the key when the server is set up, and refuses requests from a server
with no pinned key.

## 2. Signature

For each request the sender chooses a fresh random 16-byte `nonce` and takes
the current time `ts` in whole seconds since 1970-01-01 UTC:

```
n       = base64url(nonce), without padding               22 characters
payload = peer_id ‖ LF ‖ decimal(ts) ‖ LF ‖ n ‖ LF ‖ upper(method) ‖ LF ‖ path ‖ LF ‖ hex(SHA-256(body))
sig     = ML-DSA.Sign(sk, payload, ctx)
header  = "v1." ‖ decimal(ts) ‖ "." ‖ n ‖ "." ‖ base64(sig)
```

- `peer_id` is the identifier of the VPN server: the server the request goes
  to, or the server it comes from.
- `method` is the HTTP method, in ASCII capitals; `path` is the request path
  as sent, without a query string, and requests between the VPN API and the
  VPN servers carry none; `body` is the request body as sent, empty if there
  is none.
- `method` MUST be ASCII letters only. `peer_id` and `path` MUST be non-empty
  UTF-8 and MUST NOT contain a line feed (LF, 0x0A), so the payload cannot be
  read two ways.
- `decimal(ts)` has no sign and no leading zeros; `hex` is lowercase;
  `base64` is standard base64 with padding.
- `ctx` is the FIPS 204 context string, which keeps the two directions apart:

| Direction | `ctx` |
| --- | --- |
| VPN API to VPN server | `secria-vpn/api->node/v1` |
| VPN server to VPN API | `secria-vpn/node->api/v1` |

`ML-DSA.Sign` is the FIPS 204 signing algorithm, hedged or deterministic.
The header goes in the HTTP header field `X-PQ-Auth`.

## 3. Verification

The receiver:

1. splits the header at `.` into exactly four parts, the first `v1`, and
   refuses it unless `ts` is in the form above, `n` is 22 characters that
   decode to 16 bytes, and the last part is the base64 of a 3309-byte
   signature;
2. refuses it if `ts` is more than 60 seconds before or after its own clock;
3. rebuilds `payload` from the request it received and verifies `sig` with
   the sender's pinned public key and the `ctx` of the request's direction;
4. refuses the request if it accepted the same `n` 120 seconds ago or less.

A request that fails any step MUST be refused before it has any effect.

## 4. Properties

- **Post-quantum authentication.** Forging a request needs an ML-DSA
  signature under a pinned key, as well as an Ed25519 certificate.
- **Binding.** The signature covers the server, the method, the path and the
  body, so a captured header cannot be used on a different request; the
  timestamp and the nonce stop it being used again on the same one.
