# Specifications

Every format Secria uses to protect account keys, mail and VPN pre-shared
keys, and the signatures on its VPN servers, releases and warrant canary.
Where the code and these documents disagree, the documents are right.

| Document | Covers |
| --- | --- |
| [threat-model.md](threat-model.md) | What the cryptography withstands |
| [account.md](account.md) | Key sets, password-derived keys, the vault, recovery phrases, archived key sets |
| [mail.md](mail.md) | Mail format 2, and reading format 1 |
| [protected-mail.md](protected-mail.md) | Password-protected mail to people outside Secria |
| [vpn-psk.md](vpn-psk.md) | The post-quantum WireGuard pre-shared-key box, versions 1 and 2 |
| [vpn-node-auth.md](vpn-node-auth.md) | ML-DSA-65 signatures between the VPN API and VPN servers |
| [release-signatures.md](release-signatures.md) | SLH-DSA signatures on release checksums and the warrant canary |

MUST, MUST NOT, SHOULD and MAY are used as in
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) when in capitals.

## Primitives

| Name | Definition |
| --- | --- |
| `X25519(sk, pk)` | [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) section 5. An all-zero output MUST be rejected. |
| `ML-KEM-1024` | [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final). Encapsulation keys MUST pass the check of FIPS 203 section 7.2 before use. |
| `SHA3-256(m)` | [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). |
| `SHA-256(m)`, `SHA-1(m)` | [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final). SHA-1 only for the version 1 password salts ([account.md](account.md) section 2.1). |
| `HKDF(salt, ikm, info, L)` | HKDF-SHA256, [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869). |
| `HMAC-SHA256(k, m)` | [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) with SHA-256. |
| `PBKDF2-HMAC-SHA256(p, s, c, L)` | [RFC 8018](https://www.rfc-editor.org/rfc/rfc8018) section 5.2, `c` iterations, `L`-byte output. |
| `Seal(k, n, p, a)` / `Open(k, n, c, a)` | AES-256-GCM, [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final), 96-bit nonce `n`, 128-bit tag appended, associated data `a`. `Open` fails without output if the tag does not verify. |
| `Argon2id`, `Argon2d` | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106), version 0x13. Argon2d only for version 1 ([account.md](account.md) section 2.1). |
| `ML-DSA-65` | [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), with a context string. |
| `SLH-DSA-SHA2-256s` | [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final), pure, empty context string. |
| `Random(n)` | `n` bytes from the platform's cryptographically secure generator. |

Each AES-256-GCM key is used for one encryption, or with random nonces for far
fewer than 2^32, within the bounds of SP 800-38D section 8.3.

## Encoding

Integers are unsigned and big-endian.

| Notation | Encoding |
| --- | --- |
| `u8(x)`, `u32(x)` | 1 or 4 bytes |
| `vec(b)` | `u32(len(b)) ‖ b` |
| `str(s)` | `vec(UTF-8 bytes of s)` |
| `a ‖ b` | concatenation |

Every string is valid UTF-8. Implementations MUST reject strings that are
not, including JavaScript strings with unpaired surrogates, rather than
replace the invalid parts.

## Labels

VPN box version 2 starts its HKDF info and associated data with a `vec`
label of the form `secria/vpnpsk/v2/<purpose>`. A new use of a key MUST take a
label `secria/<scheme>/<version>/<purpose>` that no other use has. The other
formats use the raw ASCII strings their documents give.

## Versioning

Format 2 mail blobs and VPN box version 2 begin with a version byte. Other
objects carry none; a reader tells them apart by what the application records
with them or, where a document says so, by length. A reader MUST NOT infer a
format by trial decryption, except under the mail body rule of
[mail.md](mail.md) section 3.
