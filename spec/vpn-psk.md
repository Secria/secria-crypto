# VPN pre-shared-key box

Secria VPN gives each connection a random WireGuard pre-shared key (PSK).
WireGuard mixes the PSK into its handshake, so recorded tunnel traffic stays
confidential against an adversary who later breaks X25519. This document
specifies how the PSK travels from Secria's API to the client sealed with
ML-KEM-1024.

Primitives and encodings are defined in [README.md](README.md).

## 1. Protocol

1. For every connection the client generates a fresh ML-KEM-1024 key pair
   `(dk, ek)` and its WireGuard key pair, and sends `ek` and its WireGuard
   public key in its connect request over TLS.
2. The API chooses `psk = Random(32)`, configures it on the VPN server for
   this peer, and returns `box = SealPSK(ek, psk, …)` with the connection
   details.
3. The client opens `box` with `dk`, sets the PSK on its WireGuard peer and
   discards `dk`.

A client MUST NOT bring up the tunnel if the response carries no box, if the
box does not open, or if the response carries a PSK in the clear. A client
MUST show the connection as post-quantum protected only when it opened a box.

A client that implements version 2 sends `"psk_box_version": 2` in its
connect request. The API MUST then answer with a version 2 box, and the client
MUST refuse anything else; other clients receive version 1.

## 2. Version 2

```
(ss, ct_kem) = ML-KEM-1024.Encaps(ek)

K   = HKDF(salt = "",
           ikm  = ss,
           info = vec("secria/vpnpsk/v2/key") ‖ SHA-256(ek) ‖ SHA-256(ct_kem),
           L    = 32)

ad  = vec("secria/vpnpsk/v2/box") ‖ str(connection_id) ‖ client_wg_pk ‖ server_wg_pk

box = u8(0x02) ‖ ct_kem ‖ n ‖ Seal(K, n, psk, ad)        n = Random(12)
```

- `client_wg_pk` is the client's own 32-byte WireGuard public key, which the
  client MUST take from its own key pair, not from the response.
- `server_wg_pk` is the VPN server's 32-byte WireGuard public key and
  `connection_id` the API's identifier for the connection, a UTF-8 string of
  at most 4096 bytes; both arrive with the box.
- `psk` is the raw 32-byte WireGuard key.

A box is exactly 1629 bytes, carried in JSON as standard base64 with
padding. The associated data binds it to the client's own WireGuard key, the
server's key and the connection.

## 3. Version 1

```
K   = HKDF(salt = "", ikm = ss, info = "SecriaVPN-PSK-ML-KEM-1024-v1", L = 32)
box = ct_kem ‖ n ‖ Seal(K, n, psk_text, "")              n = Random(12)
```

`info` is raw ASCII. `psk_text` is the 44-byte standard base64 encoding of
the WireGuard key, which a reader MUST decode strictly: 44 characters of the
standard alphabet ending in one `=`, with the unused low bits of the last data
character zero ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) section
3.5). A version 1 box is exactly 1640 bytes, with no version byte and no
associated data, so it cannot be confused with version 2.

## 4. Properties

- **Harvest now, decrypt later.** An adversary who records the connect
  exchange and later breaks TLS's key exchange still needs to break
  ML-KEM-1024 to learn the PSK.
- **One key per connection.** Every connection gets a fresh PSK, and `dk`
  exists only for the lifetime of one connect request.
- **Post-quantum to the VPN server.** The channel from the VPN API to the VPN
  server MUST use a post-quantum key exchange.
