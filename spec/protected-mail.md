# Password-protected mail

A Secria account can send a password-protected message to people without a
Secria account. Each recipient gets a link to a viewer page, which derives a
key from the password in the recipient's browser, opens the message and lets
the recipient reply under the same protection. Secria's servers never receive
the password or any key that opens the message, only a verifier derived from
the password (section 2).

Primitives and encodings are defined in [README.md](README.md); the mail
format in [mail.md](mail.md).

## 1. Messages, links and the servers

The sender's client chooses for each protected message a random 32-byte
message key `K`, a random 16-byte `salt` and an iteration count. Messages to
the same recipients under the same password form a thread. Secria's servers
store with each message its salt (standard base64 with padding), iteration
count, verifier, wrapped key, body and replies.

Each recipient gets a link of its own. A sender may add a password hint, shown
to whoever holds a link. The password is taken as in
[account.md](account.md) section 2.

Secria's servers MUST follow these rules:

- Until a link holder presents the correct verifier, they give it only the
  message's salt, iteration count, hint and whether the link has expired,
  never the verifier, wrapped key, body or replies.
- They compare the presented verifier with the stored one in constant time.
- They limit wrong attempts per thread, counting every link of the thread
  together, and count each attempt before checking it.
- They give the stored verifier only to the sender's own signed-in client.
- A link expires at most 90 days after its message was sent.

## 2. Format

Protected messages use PBKDF2, so the viewer needs only Web Crypto.

```
thread_key = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
verifier   = lowercase hexadecimal of SHA-256(thread_key)
wrapped    = n ‖ Seal(thread_key, n, K, "")                 n = Random(12)
body       = format 2 blob of the message under K   (mail.md section 2)
reply      = format 2 blob under K of the reply, UTF-8 plain text
```

`salt` is 16 bytes and `wrapped` 60 bytes. `iterations` is 1,200,000, or
600,000 for a message stored without a count. A reader MUST refuse fewer than
600,000 or more than 5,000,000 iterations, and a salt that is not 16 bytes, so
a server cannot lower the work per guess below 600,000 iterations.

A reader decodes bodies and replies as format 2 only.

## 3. Opening and replying

The viewer:

1. Fetches the message's salt, iteration count and hint, and refuses them
   if they are out of range (section 2).
2. Derives `thread_key` and `verifier` from the password the recipient
   enters, and presents `verifier`.
3. Opens `wrapped` under `thread_key`, which yields the 32-byte `K`.
4. Opens the body and replies under `K` (section 2).

Replies are format 2 blobs under `K`, which the sender's client reads too.

## 4. Properties

- **Confidentiality.** A protected message and its replies can be read only
  with the password or `K`; Secria's servers hold neither.
- **Integrity.** Without the password or `K`, no one can create a format 2
  blob or alter one undetected.
- **Passwords.** Apps SHOULD require a long password, SHOULD advise sending it
  through another channel, and SHOULD warn that the hint is not secret.
