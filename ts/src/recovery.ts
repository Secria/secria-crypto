// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { hkdf } from '@noble/hashes/hkdf.js'
import { hmac } from '@noble/hashes/hmac.js'
import { BIP39_ENGLISH } from './bip39-english.js'
import { asciiLower, copyBytes, utf8 } from './bytes.js'
import { malformed } from './errors.js'
import { randomBytes, sha256, x25519Shared } from './primitives.js'

export const RECOVERY_ENTROPY_SIZE = 16
export const RECOVERY_WORDS = 12

const WORD_INDEX: ReadonlyMap<string, number> = new Map(BIP39_ENGLISH.map((w, i) => [w, i]))

export function generateRecoveryEntropy(): Uint8Array {
  return randomBytes(RECOVERY_ENTROPY_SIZE)
}

export function entropyToPhrase(entropy: Uint8Array): string[] {
  const e = checkEntropy(entropy)
  const bits = [...e].map((b) => b.toString(2).padStart(8, '0')).join('') + checksumBits(e)
  const words: string[] = []
  for (let i = 0; i < RECOVERY_WORDS; i++) {
    words.push(BIP39_ENGLISH[parseInt(bits.slice(i * 11, (i + 1) * 11), 2)]!)
  }
  return words
}

// Section 4.1. trim() and toLowerCase() would accept phrases other clients refuse.
function normaliseWord(word: string): string {
  return asciiLower(word.replace(/^[\t\n\v\f\r ]+|[\t\n\v\f\r ]+$/g, ''))
}

export function phraseToEntropy(words: readonly string[]): Uint8Array {
  if (words.length !== RECOVERY_WORDS) throw malformed('recovery phrase must be 12 words')
  let bits = ''
  for (const word of words) {
    if (typeof word !== 'string') throw malformed('recovery phrase word')
    const index = WORD_INDEX.get(normaliseWord(word))
    if (index === undefined) throw malformed('recovery phrase word')
    bits += index.toString(2).padStart(11, '0')
  }
  const entropy = new Uint8Array(RECOVERY_ENTROPY_SIZE)
  for (let i = 0; i < RECOVERY_ENTROPY_SIZE; i++) {
    entropy[i] = parseInt(bits.slice(i * 8, (i + 1) * 8), 2)
  }
  if (bits.slice(128) !== checksumBits(entropy)) throw malformed('recovery phrase checksum')
  return entropy
}

function checksumBits(entropy: Uint8Array): string {
  return (sha256(entropy)[0]! >> 4).toString(2).padStart(4, '0')
}

export function deriveRecoveryKey(entropy: Uint8Array): Uint8Array {
  return hkdf(sha256, checkEntropy(entropy), utf8('secria-recovery'), utf8('recovery-key'), 32)
}

function checkEntropy(entropy: Uint8Array): Uint8Array {
  const e = copyBytes(entropy, 'recovery entropy')
  if (e.length !== RECOVERY_ENTROPY_SIZE) throw new RangeError('recovery entropy must be 16 bytes')
  return e
}

/** Answers the server's recovery challenge (section 4.3) without revealing the phrase. */
export function recoveryProof(
  x25519Private: Uint8Array,
  ephemeralPublic: Uint8Array,
  token: string,
): Uint8Array {
  const shared = x25519Shared(x25519Private, ephemeralPublic)
  const key = hkdf(sha256, shared, utf8('secria-recovery'), utf8('recovery-proof'), 32)
  return hmac(sha256, key, utf8(token))
}
