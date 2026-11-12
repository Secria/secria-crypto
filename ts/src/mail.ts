// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import {
  checkedKeySet,
  parsePublicKeySet,
  SELF_KEY_SIZE,
  type PrivateKeySet,
  type PublicKeySet,
} from './account.js'
import { concat, copyBytes, utf8 } from './bytes.js'
import { CryptoError, malformed } from './errors.js'
import { decapsulate, encapsulate } from './mlkem.js'
import {
  aesGcmOpen,
  aesGcmSeal,
  hkdf32,
  NONCE_SIZE,
  randomBytes,
  TAG_SIZE,
  x25519Shared,
} from './primitives.js'

export const MESSAGE_KEY_SIZE = 32
const SALT_SIZE = 32

const V2_TAG = 0x02
const V2_MIN_SIZE = 1 + NONCE_SIZE + TAG_SIZE
const BLOCK = 16
const V1_MIN_SIZE = 2 * BLOCK
const INFO = utf8('message-key')
const EMPTY = new Uint8Array(0)

/** `v2-only` for every message recorded as format 2; `auto` can return unauthenticated format 1. */
export type BodyMode = 'auto' | 'v2-only'

export interface OpenedBody {
  plaintext: Uint8Array
  /** Format 1 is unauthenticated and MUST be rendered as inert text (spec/mail.md section 3). */
  format: 1 | 2
}

function decryptFailed(): CryptoError {
  return new CryptoError('authentication', 'body does not decrypt')
}

function messageKey(key: Uint8Array): Uint8Array {
  const k = copyBytes(key, 'message key')
  if (k.length !== MESSAGE_KEY_SIZE) throw malformed('message key length')
  return k
}

/** For known-answer tests only. */
export async function sealBodyWithRandomness(
  key: Uint8Array,
  plaintext: Uint8Array,
  randomness: { nonce: Uint8Array },
): Promise<Uint8Array> {
  const k = messageKey(key)
  const pt = copyBytes(plaintext, 'plaintext')
  const nonce = copyBytes(randomness.nonce, 'nonce')
  return concat(Uint8Array.of(V2_TAG), nonce, await aesGcmSeal(k, nonce, pt, EMPTY))
}

export function sealBody(key: Uint8Array, plaintext: Uint8Array): Promise<Uint8Array> {
  return sealBodyWithRandomness(key, plaintext, { nonce: randomBytes(NONCE_SIZE) })
}

export async function openBody(
  key: Uint8Array,
  blob: Uint8Array,
  mode: BodyMode,
): Promise<OpenedBody> {
  const k = messageKey(key)
  if (mode !== 'auto' && mode !== 'v2-only') throw new RangeError('unknown mode')
  const data = copyBytes(blob, 'blob')
  if (data.length >= V2_MIN_SIZE && data[0] === V2_TAG) {
    try {
      const plaintext = await aesGcmOpen(
        k,
        data.subarray(1, 1 + NONCE_SIZE),
        data.subarray(1 + NONCE_SIZE),
        EMPTY,
      )
      return { plaintext, format: 2 }
    } catch {
      if (mode === 'v2-only') throw decryptFailed()
    }
  } else if (mode === 'v2-only') {
    throw decryptFailed()
  }
  return { plaintext: await openFormat1(k, data), format: 1 }
}

async function openFormat1(key: Uint8Array, blob: Uint8Array): Promise<Uint8Array> {
  if (blob.length < V1_MIN_SIZE || blob.length % BLOCK !== 0) throw decryptFailed()
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    'raw',
    new Uint8Array(key),
    { name: 'AES-CBC' },
    false,
    ['decrypt'],
  )
  try {
    // Web Crypto checks and removes the PKCS#7 padding as section 3 requires.
    const plaintext = await globalThis.crypto.subtle.decrypt(
      { name: 'AES-CBC', iv: blob.slice(0, BLOCK) },
      cryptoKey,
      blob.slice(BLOCK),
    )
    return new Uint8Array(plaintext)
  } catch {
    throw decryptFailed()
  }
}

export interface Wrap {
  kemCiphertext: Uint8Array
  salt: Uint8Array
  wrappedKey: Uint8Array
}

export interface WrapRandomness {
  salt: Uint8Array
  nonce: Uint8Array
  encapsulationSeed?: Uint8Array
}

export function sealWrap(
  senderPrivate: Uint8Array,
  recipient: PublicKeySet,
  key: Uint8Array,
): Promise<Wrap> {
  return sealWrapWithRandomness(senderPrivate, recipient, key, {
    salt: randomBytes(SALT_SIZE),
    nonce: randomBytes(NONCE_SIZE),
  })
}

/** For known-answer tests only. */
export async function sealWrapWithRandomness(
  senderPrivate: Uint8Array,
  recipient: PublicKeySet,
  key: Uint8Array,
  randomness: WrapRandomness,
): Promise<Wrap> {
  const k = messageKey(key)
  const to = parsePublicKeySet(recipient.x25519, recipient.mlkem)
  const salt = copyBytes(randomness.salt, 'salt')
  const nonce = copyBytes(randomness.nonce, 'nonce')
  if (salt.length !== SALT_SIZE) throw new RangeError('salt must be 32 bytes')
  const sharedX = x25519Shared(senderPrivate, to.x25519)
  const { sharedKey, ciphertext } = encapsulate(to.mlkem, randomness.encapsulationSeed)
  const kek = hkdf32(salt, concat(sharedKey, sharedX), INFO)
  const wrappedKey = concat(nonce, await aesGcmSeal(kek, nonce, k, EMPTY))
  return { kemCiphertext: ciphertext, salt, wrappedKey }
}

/** `senderPublic` is the X25519 key stored with the message. */
export async function openWrap(
  recipient: PrivateKeySet,
  senderPublic: Uint8Array,
  wrap: Wrap,
): Promise<Uint8Array> {
  const own = checkedKeySet(recipient)
  const fields = {
    kemCiphertext: copyBytes(wrap.kemCiphertext, 'ML-KEM ciphertext'),
    salt: copyBytes(wrap.salt, 'salt'),
    wrappedKey: copyBytes(wrap.wrappedKey, 'wrapped key'),
  }
  const sender = copyBytes(senderPublic, 'sender public key')
  if (fields.salt.length !== SALT_SIZE) throw malformed('salt length')
  const sharedKEM = decapsulate(fields.kemCiphertext, own.mlkem)
  const sharedX = x25519Shared(own.x25519, sender)
  return unwrapMessageKey(hkdf32(fields.salt, concat(sharedKEM, sharedX), INFO), fields.wrappedKey)
}

export interface SelfWrap {
  salt: Uint8Array
  wrappedKey: Uint8Array
}

/** For known-answer tests only. */
export async function sealSelfWrapWithRandomness(
  selfKey: Uint8Array,
  key: Uint8Array,
  randomness: { salt: Uint8Array; nonce: Uint8Array },
): Promise<SelfWrap> {
  const k = messageKey(key)
  const self = copyBytes(selfKey, 'self key')
  const salt = copyBytes(randomness.salt, 'salt')
  const nonce = copyBytes(randomness.nonce, 'nonce')
  if (self.length !== SELF_KEY_SIZE) throw malformed('self key length')
  if (salt.length !== SALT_SIZE) throw new RangeError('salt must be 32 bytes')
  const kek = hkdf32(salt, self, INFO)
  return { salt, wrappedKey: concat(nonce, await aesGcmSeal(kek, nonce, k, EMPTY)) }
}

export function sealSelfWrap(selfKey: Uint8Array, key: Uint8Array): Promise<SelfWrap> {
  return sealSelfWrapWithRandomness(selfKey, key, {
    salt: randomBytes(SALT_SIZE),
    nonce: randomBytes(NONCE_SIZE),
  })
}

export async function openSelfWrap(selfKey: Uint8Array, wrap: SelfWrap): Promise<Uint8Array> {
  const key = copyBytes(selfKey, 'self key')
  const salt = copyBytes(wrap.salt, 'salt')
  const wrappedKey = copyBytes(wrap.wrappedKey, 'wrapped key')
  if (key.length !== SELF_KEY_SIZE) throw malformed('self key length')
  if (salt.length !== SALT_SIZE) throw malformed('salt length')
  return unwrapMessageKey(hkdf32(salt, key, INFO), wrappedKey)
}

async function unwrapMessageKey(kek: Uint8Array, wrappedKey: Uint8Array): Promise<Uint8Array> {
  if (wrappedKey.length !== NONCE_SIZE + MESSAGE_KEY_SIZE + TAG_SIZE) {
    throw malformed('wrapped key length')
  }
  return aesGcmOpen(kek, wrappedKey.subarray(0, NONCE_SIZE), wrappedKey.subarray(NONCE_SIZE), EMPTY)
}
