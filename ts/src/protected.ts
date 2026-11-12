// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { concat, copyBytes, hex, utf8 } from './bytes.js'
import { malformed } from './errors.js'
import {
  aesGcmOpen,
  aesGcmSeal,
  NONCE_SIZE,
  pbkdf2Sha256,
  randomBytes,
  sha256,
  TAG_SIZE,
} from './primitives.js'

export const THREAD_SALT_SIZE = 16
const KEY_SIZE = 32
const MIN_ITERATIONS = 600_000
const MAX_ITERATIONS = 5_000_000

function passwordBytes(password: string): Uint8Array {
  if (typeof password !== 'string') throw malformed('password is not a string')
  return utf8(password)
}

export function newThreadSalt(): Uint8Array {
  return randomBytes(THREAD_SALT_SIZE)
}

function checkSalt(salt: Uint8Array): Uint8Array {
  const out = copyBytes(salt, 'thread salt')
  if (out.length !== THREAD_SALT_SIZE) throw malformed('thread salt length')
  return out
}

const CONSTRUCT = Symbol('construct')

export interface NonceSource {
  nonce(): Uint8Array
}

const systemNonce: NonceSource = { nonce: () => randomBytes(NONCE_SIZE) }

export interface ThreadParams {
  readonly salt: Uint8Array
  readonly iterations: number
}

// Assigned in ThreadKey's static block, so that only this module can
// make a ThreadKey or read it.
let makeThreadKey: (key: Uint8Array) => ThreadKey
let threadKeyBytes: (k: ThreadKey) => Uint8Array

/** Never leaves the library; only the verifier goes to the server. */
export class ThreadKey {
  readonly #key: Uint8Array

  private constructor(token: symbol, key: Uint8Array) {
    if (token !== CONSTRUCT) throw new TypeError('use deriveThreadKey')
    this.#key = key
  }

  static {
    makeThreadKey = (key) => new ThreadKey(CONSTRUCT, key)
    threadKeyBytes = (k) => {
      if (!(typeof k === 'object' && k !== null && #key in k)) {
        throw new TypeError('not a ThreadKey made by this library')
      }
      return k.#key
    }
  }
}

export async function deriveThreadKey(
  password: string,
  params: ThreadParams,
): Promise<{ threadKey: ThreadKey; verifier: string }> {
  const pw = passwordBytes(password)
  if (typeof params !== 'object' || params === null) throw malformed('thread parameters')
  const salt = checkSalt(params.salt)
  const { iterations } = params
  if (!Number.isInteger(iterations) || iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS) {
    throw malformed('thread parameters out of range')
  }
  const key = await pbkdf2Sha256(pw, salt, iterations, KEY_SIZE)
  return { threadKey: makeThreadKey(key), verifier: hex(sha256(key)) }
}

export function sealProtectedKey(
  threadKey: ThreadKey,
  messageKey: Uint8Array,
): Promise<Uint8Array> {
  return sealProtectedKeyWithRandomness(threadKey, messageKey, systemNonce)
}

/** For known-answer tests only. */
export async function sealProtectedKeyWithRandomness(
  threadKey: ThreadKey,
  messageKey: Uint8Array,
  randomness: NonceSource,
): Promise<Uint8Array> {
  const tk = threadKeyBytes(threadKey)
  const k = copyBytes(messageKey, 'message key')
  if (k.length !== KEY_SIZE) throw malformed('message key length')
  const nonce = randomness.nonce()
  return concat(nonce, await aesGcmSeal(tk, nonce, k, new Uint8Array(0)))
}

export async function openProtectedKey(
  threadKey: ThreadKey,
  wrapped: Uint8Array,
): Promise<Uint8Array> {
  const tk = threadKeyBytes(threadKey)
  const data = copyBytes(wrapped, 'wrapped key')
  if (data.length !== NONCE_SIZE + KEY_SIZE + TAG_SIZE) throw malformed('wrapped key')
  return aesGcmOpen(tk, data.subarray(0, NONCE_SIZE), data.subarray(NONCE_SIZE), new Uint8Array(0))
}
