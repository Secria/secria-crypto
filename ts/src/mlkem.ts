// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { sha3_256 } from '@noble/hashes/sha3.js'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { constantTimeEqual } from './bytes.js'
import { authenticationFailed, malformed } from './errors.js'

const MLKEM_ENCAPSULATION_KEY_SIZE = 1568
export const MLKEM_DECAPSULATION_KEY_SIZE = 3168
const MLKEM_CIPHERTEXT_SIZE = 1568
const MLKEM_ENCAPSULATION_SEED_SIZE = 32

const Q = 3329
// ByteEncode12 of k = 4 polynomials: t-hat in an encapsulation key, s-hat in a decapsulation key.
const VECTOR_BYTES = 4 * 384

/** FIPS 203 section 7.2. */
export function checkEncapsulationKey(ek: Uint8Array): void {
  if (ek.length !== MLKEM_ENCAPSULATION_KEY_SIZE) {
    throw malformed('ML-KEM-1024 encapsulation key length')
  }
  for (let i = 0; i < VECTOR_BYTES; i += 3) {
    const b0 = ek[i]!
    const b1 = ek[i + 1]!
    const b2 = ek[i + 2]!
    const c0 = b0 | ((b1 & 0x0f) << 8)
    const c1 = (b1 >> 4) | (b2 << 4)
    if (c0 >= Q || c1 >= Q) throw malformed('ML-KEM-1024 encapsulation key coefficient')
  }
}

/** FIPS 203 section 7.3. Returns the embedded encapsulation key. */
export function checkDecapsulationKey(dk: Uint8Array): Uint8Array {
  if (dk.length !== MLKEM_DECAPSULATION_KEY_SIZE) {
    throw malformed('ML-KEM-1024 decapsulation key length')
  }
  const ek = dk.subarray(VECTOR_BYTES, VECTOR_BYTES + MLKEM_ENCAPSULATION_KEY_SIZE)
  const hash = dk.subarray(
    VECTOR_BYTES + MLKEM_ENCAPSULATION_KEY_SIZE,
    VECTOR_BYTES + MLKEM_ENCAPSULATION_KEY_SIZE + 32,
  )
  if (!constantTimeEqual(sha3_256(ek), hash)) throw malformed('ML-KEM-1024 decapsulation key hash')
  checkEncapsulationKey(ek)
  return ek
}

export interface Encapsulation {
  sharedKey: Uint8Array
  ciphertext: Uint8Array
}

/** `m` fixes the randomness, for known-answer tests only. */
export function encapsulate(ek: Uint8Array, m?: Uint8Array): Encapsulation {
  checkEncapsulationKey(ek)
  if (m !== undefined && m.length !== MLKEM_ENCAPSULATION_SEED_SIZE) {
    throw new RangeError('encapsulation randomness must be 32 bytes')
  }
  const { cipherText, sharedSecret } = ml_kem1024.encapsulate(ek, m)
  return { sharedKey: sharedSecret, ciphertext: cipherText }
}

export function decapsulate(ciphertext: Uint8Array, dk: Uint8Array): Uint8Array {
  if (ciphertext.length !== MLKEM_CIPHERTEXT_SIZE) throw malformed('ML-KEM-1024 ciphertext length')
  if (dk.length !== MLKEM_DECAPSULATION_KEY_SIZE) {
    throw malformed('ML-KEM-1024 decapsulation key length')
  }
  try {
    return ml_kem1024.decapsulate(ciphertext, dk)
  } catch {
    throw authenticationFailed()
  }
}

export interface MlKemKeyPair {
  encapsulationKey: Uint8Array
  decapsulationKey: Uint8Array
}

export function generateKeyPair(): MlKemKeyPair {
  const { publicKey, secretKey } = ml_kem1024.keygen()
  return { encapsulationKey: publicKey, decapsulationKey: secretKey }
}
