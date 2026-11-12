// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { x25519 } from '@noble/curves/ed25519.js'
import { hkdf } from '@noble/hashes/hkdf.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { authenticationFailed, malformed } from './errors.js'
import { copyBytes, isAllZero } from './bytes.js'

const AES_KEY_SIZE = 32
export const NONCE_SIZE = 12
export const TAG_SIZE = 16
export const X25519_KEY_SIZE = 32

const subtle = globalThis.crypto.subtle

export function randomBytes(n: number): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(n))
}

function importKey(key: Uint8Array, usage: 'encrypt' | 'decrypt'): Promise<CryptoKey> {
  const k = copyBytes(key, 'AES-256-GCM key')
  if (k.length !== AES_KEY_SIZE) throw new RangeError('AES-256-GCM key must be 32 bytes')
  return subtle.importKey('raw', k, { name: 'AES-GCM' }, false, [usage])
}

export async function aesGcmSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  // Every input is copied before the first await, so a caller that changes its
  // buffers during the call cannot change what is sealed.
  const iv = copyBytes(nonce, 'nonce')
  const ad = copyBytes(additionalData, 'associated data')
  const pt = copyBytes(plaintext, 'plaintext')
  if (iv.length !== NONCE_SIZE) throw new RangeError('AES-GCM nonce must be 12 bytes')
  const cryptoKey = await importKey(key, 'encrypt')
  const ct = await subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 },
    cryptoKey,
    pt,
  )
  return new Uint8Array(ct)
}

export async function aesGcmOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  additionalData: Uint8Array,
): Promise<Uint8Array> {
  const iv = copyBytes(nonce, 'nonce')
  const ad = copyBytes(additionalData, 'associated data')
  const ct = copyBytes(ciphertext, 'ciphertext')
  if (iv.length !== NONCE_SIZE || ct.length < TAG_SIZE) throw authenticationFailed()
  const cryptoKey = await importKey(key, 'decrypt')
  try {
    const pt = await subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 },
      cryptoKey,
      ct,
    )
    return new Uint8Array(pt)
  } catch {
    throw authenticationFailed()
  }
}

export async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  length: number,
): Promise<Uint8Array> {
  const material = await subtle.importKey('raw', new Uint8Array(password), 'PBKDF2', false, [
    'deriveBits',
  ])
  const bits = await subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(salt), iterations },
    material,
    length * 8,
  )
  return new Uint8Array(bits)
}

export function hkdf32(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array): Uint8Array {
  return hkdf(sha256, ikm, salt, info, 32)
}

export { sha256 }

export function x25519PublicKey(privateKey: Uint8Array): Uint8Array {
  const sk = copyBytes(privateKey, 'X25519 private key')
  if (sk.length !== X25519_KEY_SIZE) throw malformed('X25519 private key length')
  return x25519.getPublicKey(sk)
}

export function x25519Shared(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
  const sk = copyBytes(privateKey, 'X25519 private key')
  const pk = copyBytes(publicKey, 'X25519 public key')
  if (sk.length !== X25519_KEY_SIZE || pk.length !== X25519_KEY_SIZE) {
    throw malformed('X25519 key length')
  }
  let shared: Uint8Array
  try {
    shared = x25519.getSharedSecret(sk, pk)
  } catch {
    throw malformed('X25519 public key of low order')
  }
  if (isAllZero(shared)) throw malformed('X25519 public key of low order')
  return shared
}
