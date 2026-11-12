# Mail encryption

A message's body and attachments are encrypted once, under a random message
key. The message key is wrapped for each Secria recipient under a key derived
from both an ML-KEM-1024 encapsulation and an X25519 exchange, and for the
sender's own copy under the sender's self key. Secria's apps and mail server
write format 2. Format 1, which older app versions wrote, is specified so
readers can open it (section 3).

Primitives and encodings are defined in [README.md](README.md); account keys,
`self_key` and `key_id` in [account.md](account.md).

## 1. Overview

```
K          = Random(32)                  message key, one per message
body       = blob of the body under K                       section 2
attachment = blob of each attachment under K                section 2
wrap_R     = K wrapped for each Secria recipient R          section 4
wrap_self  = K wrapped under the sender's self_key          section 5
x_pk_S     = the sender-side X25519 public key, once per message
```

Fields are raw bytes; how an application stores them is outside this
specification unless a section says otherwise.

A writer MUST generate `K` afresh for each message, and MUST seal nothing under
it but that message's body and attachments and, for a password-protected
message, its replies ([protected-mail.md](protected-mail.md) section 2).

## 2. Bodies and attachments

The body and each attachment are sealed separately under `K`:

```
format 2:  u8(0x02) ‖ n ‖ Seal(K, n, plaintext, "")        n  = Random(12)
format 1:  iv ‖ AES-256-CBC(K, iv, PKCS#7(plaintext))     iv = Random(16)
```

A format 2 blob is 29 bytes longer than its plaintext: version byte, 12-byte
nonce, 16-byte tag. A format 1 blob is a 16-byte IV and the AES-256-CBC
encryption ([NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final))
of the plaintext with PKCS#7 padding
([RFC 5652](https://www.rfc-editor.org/rfc/rfc5652) section 6.3).

The body's plaintext is the message's MIME content; an attachment's is the
file's content.

Writers MUST write format 2 and record with each message that it is format 2.

## 3. Reading a body

A format 1 blob begins with its random IV, so about one in 256 begins with
`0x02`. Where a message is recorded as format 2, a reader MUST decode its
blobs as format 2 only. Otherwise:

1. If the blob begins with `0x02` and is at least 29 bytes long, open it as
   format 2. If `Open` succeeds, the blob is format 2 and its plaintext is the
   result.
2. Otherwise decode it as format 1. This MUST fail unless the blob is at least
   32 bytes long and a multiple of 16 bytes, and the decrypted padding is well
   formed: its last byte `p` is between 1 and 16 and the last `p` bytes all
   equal `p`.

Format 1 has no authentication. Against EFAIL-style attacks, applications
MUST render content that opened as format 1 as inert text, without remote
resources or active content, and label it as an older format.
A reader MUST treat every decryption failure alike and MUST NOT reveal which
step failed beyond what it logs locally.

A client SHOULD record locally which messages it has opened as format 2, and
decode those as format 2 only, whatever the server's record says.

## 4. Recipient wrap

A sender wraps `K` once for each Secria recipient, to the key set Secria's
key directory serves for that address. For a recipient `R` with public keys
`R.x_pk` and `R.kem_ek`, and a sender X25519 private key `x_sk_S`:

```
(ss_kem, ct_kem) = ML-KEM-1024.Encaps(R.kem_ek)
ss_x             = X25519(x_sk_S, R.x_pk)
salt             = Random(32)
KEK              = HKDF(salt = salt, ikm = ss_kem ‖ ss_x,
                        info = "message-key", L = 32)
wrapped_key      = n ‖ Seal(KEK, n, K, "")                 n = Random(12)
```

`info` is raw ASCII. A wrap is `ct_kem` (1568 bytes), `salt` (32 bytes) and
`wrapped_key` (60 bytes). The message stores `x_pk_S = X25519(x_sk_S, 9)` once
for all its wraps. `x_sk_S` is:

| Message | `x_sk_S` |
| --- | --- |
| Written by a Secria account's app | The account's X25519 private key ([account.md](account.md) section 1) |
| Received by the mail server from another provider | An inbound key the mail server generates and replaces every 12 hours |
| Written by Secria's servers (section 6) | A key generated for that message |

The mail server records with each wrap the `key_id` it wrapped to. The
recipient opens the wrap:

```
ss_kem = ML-KEM-1024.Decaps(R.kem_dk, ct_kem)
ss_x   = X25519(R.x_sk, x_pk_S)
KEK    = HKDF(salt = salt, ikm = ss_kem ‖ ss_x, info = "message-key", L = 32)
K      = Open(KEK, n, c, "")                 where wrapped_key = n ‖ c
```

A reader MUST reject a wrap whose `ct_kem`, `salt` or `wrapped_key` is not
1568, 32 or 60 bytes, and an `x_pk_S` for which `ss_x` is all zero. A wrap for
another key set, or an altered `ct_kem`, shows as `Open` failing.

A reader whose current key set does not open a message's key MAY try its self
wrap (section 5) and each of its other key sets, archived ones included
([account.md](account.md) section 5). Each attempt is a full AES-256-GCM
`Open`, so a wrong key yields nothing.

`KEK` is derived from both shared secrets. With HKDF-Extract modelled as a
random oracle, `KEK` is indistinguishable from random to an adversary missing
either `ss_kem` or `ss_x`, so `K` stays secret while either ML-KEM-1024 or
X25519 is unbroken.

## 5. Self wrap

The sender's own copy of each message it sends, and of each draft it saves,
carries a self wrap of `K` under the sender's `self_key`:

```
salt        = Random(32)
KEK_self    = HKDF(salt = salt, ikm = self_key, info = "message-key", L = 32)
wrapped_key = n ‖ Seal(KEK_self, n, K, "")                 n = Random(12)
```

The copy stores `salt` (32 bytes) and `wrapped_key` (60 bytes); a reader MUST
reject other lengths. Only a holder of `self_key` can make or open a self
wrap.

## 6. Other providers, and mail the servers write

- **Sending to another provider.** The sender's app gives the mail server the
  message's `K`; the server opens the message (section 3) and delivers it by
  SMTP. The copies stored for the sender and Secria recipients stay encrypted
  (sections 4 and 5).
- **Receiving from another provider.** The mail server generates `K`, seals
  the body and each attachment in format 2, wraps `K` for each Secria
  recipient with its inbound key (section 4), records it as format 2, and
  stores the body and attachments only encrypted.
- **Mail the servers write.** Mail Secria's servers place in a mailbox
  themselves, such as an automatic reply's copy or the notice of a
  password-protected message, MUST be sealed the same way under a key
  generated for it, and recorded as format 2.

## 7. Properties

- **Confidentiality.** The body and attachments of a message between Secria
  accounts can be read only with a recipient's private keys or the sender's
  `self_key`, while either ML-KEM-1024 or X25519 is unbroken, Secria's servers
  included.
- **Post-quantum.** A recorded wrap stays closed to an adversary who breaks
  X25519 until it also breaks ML-KEM-1024.
- **Integrity.** No one without `K` can alter the blobs of a message recorded
  as format 2 undetected.
- **Recipient isolation.** Each recipient's wrap is sealed to that
  recipient's keys alone; opening it reveals nothing about another
  recipient's keys.
- **Sender.** Secria's servers send mail only from addresses the sending
  account owns, and refuse mail from other providers that claims a Secria
  address.
