// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { checkKeySet, keyId, type PrivateKeySet } from '../src/account.js'
import { x25519PublicKey } from '../src/primitives.js'

export function fromHex(s: string): Uint8Array {
  if (s.length % 2 !== 0) throw new Error('odd-length hex')
  return Uint8Array.from(s.match(/../g) ?? [], (b) => parseInt(b, 16))
}

export function readVectors<T>(name: string): T {
  const path = fileURLToPath(new URL(`../../test-vectors/${name}`, import.meta.url))
  return JSON.parse(readFileSync(path, 'utf8')) as T
}

/** The ML-KEM-1024 key pair of FIPS 203 ML-KEM.KeyGen_internal for a 64-byte seed d ‖ z. */
export function keyPairFromSeed(seed: Uint8Array) {
  const { publicKey, secretKey } = ml_kem1024.keygen(seed)
  return { encapsulationKey: publicKey, decapsulationKey: secretKey }
}

/** A key set whose ML-KEM key comes from a 64-byte FIPS 203 seed, as the vectors give it. */
export function keySetFromSeed(
  x25519Private: Uint8Array,
  mlkemSeed: Uint8Array,
  selfKey: Uint8Array = new Uint8Array(32).fill(7),
): PrivateKeySet {
  const kem = keyPairFromSeed(mlkemSeed)
  const x25519Public = x25519PublicKey(x25519Private)
  return checkKeySet(
    { x25519: x25519Private, mlkem: kem.decapsulationKey, selfKey },
    x25519Public,
    kem.encapsulationKey,
    keyId(x25519Public, kem.encapsulationKey),
  )
}

/** A key set's fields, private keys included, which object spread and toEqual do not see. */
export function keyParts(k: PrivateKeySet) {
  return { x25519: k.x25519, mlkem: k.mlkem, selfKey: k.selfKey, publicKey: k.publicKey }
}
