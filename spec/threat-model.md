# Threat model

What Secria's cryptography withstands. The mail, protected-mail, VPN and
release documents give each scheme's exact properties.

## Parties

| Party | Assumed capability |
| --- | --- |
| Network attacker | Reads, records, delays and modifies all traffic. |
| Secria's servers | Store and serve every ciphertext, header and public key, receive each account's login hash at sign-in, and handle mail to and from other providers. May be compromised or compelled at any time. |
| Other users | Hold their own keys; may be recipients of the same message. |
| Future quantum adversary | Breaks X25519, other elliptic-curve problems and RSA, including in recordings of past traffic; does not break ML-KEM-1024, AES-256, SHA-256 or HKDF. |

## Goals

1. The bodies and attachments of mail between Secria accounts, and every
   account's private keys, are readable only with that account's keys, even by
   an attacker who obtains everything Secria's servers store. Mail from other
   providers is stored encrypted to its recipients' keys from the moment the
   mail server receives it.
2. Mail encrypted to Secria accounts' keys, and VPN tunnels whose pre-shared
   key is sealed with ML-KEM-1024, stay confidential against a future quantum
   adversary that records them today.
3. A guess at an account password can be tested only by running Argon2 with
   the parameters of [account.md](account.md) section 2.
4. The VPN API and every VPN server authenticate each request between them
   with ML-DSA-65 ([vpn-node-auth.md](vpn-node-auth.md)), and Secria's release
   checksum lists and warrant canary carry SLH-DSA signatures
   ([release-signatures.md](release-signatures.md)).

## Out of scope

- A compromised device: malware on a user's device sees what the user sees.
- Traffic analysis: who mails whom, when, and how much.
