<p align="center">
  <a href="https://secria.me">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset=".github/assets/secria-dark.svg">
      <img src=".github/assets/secria.svg" alt="Secria" width="260">
    </picture>
  </a>
</p>

<h3 align="center">Post-quantum encryption behind Secria Mail and Secria VPN</h3>

<p align="center">
  <a href="https://github.com/Secria/secria-crypto/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Secria/secria-crypto/ci.yml?branch=main&label=tests" alt="Tests"></a>
  <a href="https://pkg.go.dev/github.com/Secria/secria-crypto/go"><img src="https://img.shields.io/badge/go-reference-2C00FF?logo=go&logoColor=white" alt="Go reference"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-AGPL--3.0-2C00FF" alt="Licence: AGPL-3.0"></a>
</p>

<p align="center">
  <a href="https://secria.me/whitepaper/mail/">Mail whitepaper</a> ·
  <a href="https://secria.me/whitepaper/vpn/">VPN whitepaper</a> ·
  <a href="spec/">Specifications</a> ·
  <a href="SECURITY.md">Security</a>
</p>

Specifications and reference implementations of the encryption behind Secria
Mail and Secria VPN, of the post-quantum signatures between Secria's VPN API
and VPN servers, and of the signatures on its releases and warrant canary.

- **End to end.** Mail between Secria accounts is encrypted in the sender's
  app and decrypted in each recipient's.
- **Zero access.** Stored mail bodies and attachments are encrypted to the
  account's keys, including mail from other providers as it arrives. Private
  keys reach Secria's servers only wrapped under a key derived on the device
  from the password or the recovery phrase.
- **Post-quantum.** Every message key is wrapped for each Secria recipient
  under ML-KEM-1024 and X25519 together. The VPN API seals the WireGuard
  pre-shared key to an ML-KEM-1024 key the app sends.

| Directory | Contents |
| --- | --- |
| [`spec/`](spec/) | [Threat model](spec/threat-model.md), [account keys](spec/account.md), [mail](spec/mail.md), [password-protected mail](spec/protected-mail.md), [VPN pre-shared keys](spec/vpn-psk.md), [VPN API and server request signatures](spec/vpn-node-auth.md), [release and canary signatures](spec/release-signatures.md) |
| [`go/`](go/) | Mail as the mail server writes it, the VPN pre-shared-key box, ML-DSA-65 request signatures between the VPN API and servers, SLH-DSA release and canary verification |
| [`ts/`](ts/) | Account keys, recovery phrases, mail and password-protected mail, in the formats the web and mobile apps use |
| [`test-vectors/`](test-vectors/) | Known-answer vectors, output captured from Secria's apps and servers, and signed release checksums and canary |

Secria's apps and mail server write mail format 2 and read format 1. The VPN
API seals pre-shared keys with the Go package, and `nodeauth` and `release`
interoperate with Secria's VPN servers and release signing. The
implementations here open the output captured in
[`deployed.json`](test-vectors/deployed.json) and
[`deployed-platforms.json`](test-vectors/deployed-platforms.json).

## Build and test

Go 1.26 or later.

```sh
cd go
go vet ./...
go test ./...
```

Node.js 22.12 or later, 24, or 26 or later.

```sh
cd ts
npm ci
npm run typecheck
npm test
```

## Use

- **Go:** `go get github.com/Secria/secria-crypto/go`. `mail` and `vpnpsk` use
  only the standard library; `nodeauth` and `release` use
  [CIRCL](https://github.com/cloudflare/circl).
- **Verify a download:** `release.VerifyManifest` checks the signature on a
  `SHA256SUMS` list against the release key at `https://secria.me/keys/release-slhdsa.pub`.
- **TypeScript:** `npm pack` in `ts/` builds `secria-crypto-<version>.tgz`.
  Argon2id runs on `@noble/hashes` unless the caller passes a faster
  WebAssembly implementation.

## Test vectors

| File | Produced by | Checked by |
| --- | --- | --- |
| `mail.json` | Go | Go and TypeScript |
| `account.json` | TypeScript | TypeScript, against a second Argon2id implementation |
| `protected-mail.json` | TypeScript | TypeScript, against `node:crypto` |
| `vpn-psk.json`, `vpn-node-auth.json` | Go | Go |
| `release/` | Secria's release and canary keys | Go |
| `deployed.json`, `deployed-platforms.json` | Secria's apps, mail server and VPN API | Go and TypeScript |

`go test ./mail ./vpnpsk ./nodeauth -run TestVectors -update` and
`UPDATE_VECTORS=1 npx vitest run test/account.test.ts test/protected.test.ts`
regenerate the first five. A change to a vector is a change to a format and
comes with a change to the specification.

## Dependencies

| Implementation | Dependency | Used for |
| --- | --- | --- |
| Go | Standard library | ML-KEM-1024, X25519, HKDF, AES-GCM |
| Go | [CIRCL](https://github.com/cloudflare/circl) | ML-DSA-65, SLH-DSA-SHA2-256s |
| TypeScript | [`@noble/hashes`](https://github.com/paulmillr/noble-hashes), [`@noble/curves`](https://github.com/paulmillr/noble-curves) | SHA-2, SHA-3, HKDF, HMAC, Argon2id, X25519 |
| TypeScript | [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) | ML-KEM-1024 |
| TypeScript | Web Crypto | AES-256-GCM, AES-256-CBC, PBKDF2, random numbers |

Secria's apps implement the same formats on
[`mlkem`](https://github.com/dajiaji/crystals-kyber-js) and
[`argon2-browser`](https://github.com/antelle/argon2-browser), as the
[Mail whitepaper](https://secria.me/whitepaper/mail/) lists. The
implementations here open the apps' captured output byte for byte
([`deployed.json`](test-vectors/deployed.json)).

## Security

Report vulnerabilities as [SECURITY.md](SECURITY.md) describes. This
repository does not take pull requests.

## Licence

Copyright 2026 Secria, Inc. Licensed under
[AGPL-3.0-only](LICENSE); third-party material is listed in [NOTICE](NOTICE).
The licence grants no rights to the Secria name or logo. For other terms,
write to hq@secria.me.
