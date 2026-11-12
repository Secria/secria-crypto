# Release and canary signatures

Secria signs the checksum lists of every release download, and its warrant
canary, with SLH-DSA-SHA2-256s (FIPS 205), whose security rests only on hash
functions. This document specifies both signatures so anyone can check them.

## 1. Scheme and keys

Both signatures are pure SLH-DSA-SHA2-256s (FIPS 205 section 10.2) with an
empty context string. Public keys are 64 bytes and signatures 29,792 bytes.
Secria signs deterministically; a verifier accepts any valid signature.

There are two key pairs:

| Key | Signs | Public key published |
| --- | --- | --- |
| Release key | Checksum lists | `https://secria.me/keys/release-slhdsa.pub` |
| Canary key | The warrant canary | In each VPN app, which pins it, and with the canary itself |

Keys and signatures published as files use the textual encoding of
[RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) with the labels
`SLH-DSA PUBLIC KEY` and `SLH-DSA SIGNATURE`, and no headers.

## 2. Checksum lists

A checksum list, such as `SHA256SUMS`, has one line for each download: the
file's SHA-256 in lowercase hexadecimal, two spaces and the file name. The
signature covers the list's bytes exactly as published, and is published
next to it with `.sig` appended to its name.

To check a download, a user verifies the list's signature with the release
public key, then compares the download's SHA-256 with its line in the list.
A list whose signature does not verify MUST NOT be used.

## 3. Warrant canary

The VPN API serves the canary at `/api/v1/canary` as JSON:

| Field | Value |
| --- | --- |
| `statement` | The statement, one line |
| `date` | The date it was made, `YYYY-MM-DD` |
| `next_update` | The date by which the next one will be published, `YYYY-MM-DD` |
| `sig_algo` | `SLH-DSA-SHA2-256s` |
| `signature` | Standard base64 of the signature |
| `public_key` | Standard base64 of the canary public key |

The signature covers:

```
statement ‖ LF ‖ date ‖ LF ‖ next_update
```

with no trailing line feed. None of the three fields may be empty or contain
a line feed.

An app MUST verify the signature with the key it pins, not the
`public_key` the response carries, MUST refuse any `sig_algo` other than
`SLH-DSA-SHA2-256s`, and MUST treat a canary as not renewed once 24 hours have
passed after its `next_update`, or if its `next_update` does not parse.

## 4. Properties

- **Post-quantum.** Forging a signature needs a break of SHA-256 and
  SHA-512 as FIPS 205 uses them; a quantum computer does not help beyond
  Grover's algorithm, against which SLH-DSA-SHA2-256s keeps 128 bits.
