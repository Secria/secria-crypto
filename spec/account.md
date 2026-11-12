# Account keys

Each account has one current key set. Its private keys leave a client only
wrapped: under a key derived from the password (the vault) and, if the user
created one, under a key derived from a recovery phrase.

Primitives and encodings are defined in [README.md](README.md).

## 1. Key set

| Key | Private part | Public part |
| --- | --- | --- |
| X25519 | `x_sk`: `Random(32)` | `x_pk = X25519(x_sk, 9)`, 32 bytes |
| ML-KEM-1024 | `kem_dk`: the 3168-byte decapsulation key of FIPS 203 `ML-KEM.KeyGen` | `kem_ek`: 1568 bytes |
| Self key | `self_key`: `Random(32)`; protects the account's own copy of each message | none |

```
key_id = SHA-256(x_pk ‖ kem_ek)
```

`key_id` is 32 bytes. Interfaces that carry it as text use standard base64
with padding ([RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) section 4).

A stored identifier of any other length MUST be refused. `kem_dk` is stored
in its expanded 3168-byte form.

A client that loads a key set, from the vault, from recovery or from local
storage, MUST refuse it unless all of these hold:

1. `x_sk` is 32 bytes and `X25519(x_sk, 9) = x_pk`.
2. `kem_dk` is 3168 bytes and passes the decapsulation-key check of FIPS 203
   section 7.3: the hash stored in `kem_dk` equals `SHA3-256` of the
   encapsulation key embedded in `kem_dk`.
3. The encapsulation key embedded in `kem_dk` equals `kem_ek`, and `kem_ek`
   passes the encapsulation-key check of FIPS 203 section 7.2.
4. `self_key` is 32 bytes and differs from `x_sk`.
5. The stored `key_id` matches `x_pk ‖ kem_ek`, as described above.

These checks stop a server from pairing a user's private keys with public
keys other than their own.

A key set is replaced only when the account is reset by recovery email
(section 5). A password change and recovery by phrase keep it, and the
servers MUST refuse a different key set on those paths.

`self_key` is used only as HKDF input keying material, each use with its own
salt and info:

| Use | Derivation |
| --- | --- |
| Mail self wrap, for sent mail and drafts | [mail.md](mail.md) section 5 |
| Archived key sets | Section 5 |
| The deployed apps' local storage: search index, offline mail, offline queries, outbox | `HKDF(salt = "", ikm = self_key, info = s, L = 32)`, where `s` is the raw ASCII string `"secria-search-v1"`, `"secria-offline-v1"` (phone apps, offline mail), `"secria-offline-v2"` (web app, offline mail and queries), `"secria-offline-v2-query"` (web app, an HMAC-SHA256 key that names each stored query) or `"secria-outbox-v1"` |
| Secria Workspace: calendars, the people directory and the saved search index | HKDF, each with an info string distinct from those above |

A new local use MUST take `salt = ""` and
`info = vec("secria/local/v1/<purpose>")`.

## 2. Password-derived keys

A client derives two values from the password: the login hash, which it sends
to the server at sign-in, and the vault key, which it keeps. Both take the
account's canonical address: its primary address, in ASCII, with letters in
lowercase and an internationalised domain in its `xn--` form. A client MUST
derive both from the address the user entered to sign in, put into that form
on the device, never from an address the server supplies. The password is the
UTF-8 encoding of what the user entered, without Unicode normalisation.
Argon2id's secret and associated-data inputs are empty.

```
login_salt = ASCII(base64(SHA-256(UTF-8(address))))
vault_salt = ASCII(base64(SHA-256(UTF-8("vault" ‖ address))))

login_hash = Argon2id(password, login_salt, t = 3, m = 65536 KiB, p = 1, T = 32)
vault_key  = Argon2id(password, vault_salt, t = 3, m = 65536 KiB, p = 1, T = 32)
```

`base64` is standard base64 with padding, so each salt is 44 ASCII bytes. The
client sends `login_hash` as 64 lowercase hexadecimal characters. The salts
depend only on the address, so a client derives both values before it
contacts the server.

The server MUST treat `login_hash` as a password and store only a salted, slow
hash of it. It MUST NOT allow two accounts whose primary addresses differ only
by a leading `vault`.

### 2.1 Version 1 (Argon2d)

The Secria VPN apps use version 1, with addresses and passwords taken as in
section 2. The Mail apps derive version 1 alongside section 2, so one password
opens both. The application records which versions each account has.

```
login_salt = ASCII(base64(SHA-1(UTF-8(address))))
vault_salt = ASCII(base64(SHA-1(UTF-8("vault" ‖ address))))

login_hash = Argon2d(password, login_salt, t = 3, m = 65536 KiB, p = 1, T = 24)
vault_key  = Argon2d(password, vault_salt, t = 3, m = 65536 KiB, p = 1, T = 32)
```

Each salt is 28 ASCII bytes. The 24-byte login hash is sent as 48 lowercase
hexadecimal characters. SHA-1 only makes a fixed-length salt from the
address.

## 3. Vault

The vault holds the three private keys of a key set, each wrapped separately
under `vault_key`:

```
wrap(secret) = n ‖ Seal(vault_key, n, secret, "")          n = Random(12)
```

`secret` is `x_sk`, `kem_dk` or `self_key`, so the wraps are 60, 3196 and 60
bytes. They carry no version byte and no associated data. A client that opens
the vault MUST apply the checks of section 1 against the stored public keys
and `key_id`, and treat a failed check like a failed `Open`; checks 1 and 4
catch a swap of the two 60-byte wraps.

## 4. Recovery phrase

### 4.1 Phrase

```
entropy = Random(16)
phrase  = BIP-39 English mnemonic of entropy (12 words)
```

The mnemonic follows
[BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki): the
128 entropy bits and the first 4 bits of `SHA-256(entropy)`, split into twelve
11-bit indices into the English wordlist. Each word is compared with the list
after trimming U+0009 to U+000D and U+0020 from both ends and lowercasing ASCII
letters. A decoder MUST reject words outside the list and a checksum that does
not match. The BIP-39 PBKDF2 seed is not used.

### 4.2 Recovery key and wraps

```
recovery_key = HKDF(salt = "secria-recovery", ikm = entropy,
                    info = "recovery-key", L = 32)
```

The salt and info are raw ASCII. The recovery wraps are the wraps of section
3 under `recovery_key`, checked the same way. A new recovery phrase gets new
recovery wraps.

### 4.3 Proof of possession

During recovery the server sends a challenge: an ephemeral X25519 public key
`eph_pk` (32 bytes) and a single-use `token` string. The client answers:

```
shared = X25519(x_sk, eph_pk)
k      = HKDF(salt = "secria-recovery", ikm = shared,
              info = "recovery-proof", L = 32)
proof  = HMAC-SHA256(k, UTF-8(token))
```

The client MUST reject an `eph_pk` for which `shared` is all zero. The
server computes the same value from its ephemeral private key and the
account's `x_pk`. The proof shows possession of `x_sk`, which the client gets
by opening the recovery wraps; the distinct salt and info keep `k` apart from
every mail key.

## 5. Archived key sets

When an account is reset by recovery email, its key set is replaced. The
client keeps each earlier key set it can open, sealed under the current self
key, so mail wrapped to it stays readable. The server keeps the earlier
vault and recovery wraps, so the old password or recovery phrase opens the
earlier key set later.

```
archive_key = HKDF(salt = "secria-archived-keys", ikm = self_key,
                   info = "seal", L = 32)
archived    = n ‖ Seal(archive_key, n, old.x_sk ‖ old.kem_dk ‖ old.self_key, ad)
  n  = Random(12)
  ad = ASCII(base64(old.key_id))
```

`self_key` is the current key set's; the salt and info are raw ASCII.
`archived` is 3260 bytes, with no version byte. On opening, a client derives
`old.x_pk` and `old.kem_ek` from the private keys and MUST apply the checks of
section 1 against `old.key_id`.
