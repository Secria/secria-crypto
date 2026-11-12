// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { createDecipheriv, pbkdf2Sync } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { concat, hex, utf8 } from '../src/bytes.js'
import { openBody, sealBodyWithRandomness } from '../src/mail.js'
import {
  deriveThreadKey,
  newThreadSalt,
  openProtectedKey,
  sealProtectedKeyWithRandomness,
} from '../src/protected.js'
import { sha256 } from '../src/primitives.js'
import { fromHex, readVectors } from './helpers.js'

const code = (c: string) => expect.objectContaining({ code: c })

/** Deterministic test bytes: SHA-256("secria-crypto test vectors" ‖ label ‖ u32(counter)), concatenated. */
function testBytes(name: string, n: number): Uint8Array {
  const out: Uint8Array[] = []
  for (let counter = 0; out.length * 32 < n; counter++) {
    const c = new Uint8Array(4)
    new DataView(c.buffer).setUint32(0, counter)
    out.push(sha256(concat(utf8('secria-crypto test vectors'), utf8(name), c)))
  }
  return concat(...out).subarray(0, n)
}

/** AES-256-GCM decryption through node:crypto. */
function nodeGcmOpen(key: Uint8Array, nonce: Uint8Array, sealed: Uint8Array, ad: Uint8Array) {
  const d = createDecipheriv('aes-256-gcm', key, nonce)
  d.setAAD(ad)
  d.setAuthTag(sealed.subarray(sealed.length - 16))
  return new Uint8Array(
    Buffer.concat([d.update(sealed.subarray(0, sealed.length - 16)), d.final()]),
  )
}

describe('password-protected mail', () => {
  const params = { salt: testBytes('thread salt', 16), iterations: 600_000 }

  it('matches PBKDF2 from node:crypto and opens the wrapped key and body', async () => {
    const { threadKey, verifier } = await deriveThreadKey('correct horse', params)
    const expected = pbkdf2Sync(utf8('correct horse'), params.salt, 600_000, 32, 'sha256')
    expect(verifier).toBe(hex(sha256(new Uint8Array(expected))))

    const messageKey = testBytes('message key', 32)
    const wrapped = await sealProtectedKeyWithRandomness(threadKey, messageKey, {
      nonce: () => testBytes('wrap nonce', 12),
    })
    expect(await openProtectedKey(threadKey, wrapped)).toEqual(messageKey)
    await expect(openProtectedKey(threadKey, wrapped.subarray(1))).rejects.toThrow(
      code('malformed'),
    )
    const body = await sealBodyWithRandomness(messageKey, utf8('hello'), {
      nonce: testBytes('body nonce', 12),
    })
    expect((await openBody(messageKey, body, 'v2-only')).plaintext).toEqual(utf8('hello'))
    expect(newThreadSalt().length).toBe(16)
    expect(JSON.stringify(threadKey)).toBe('{}')
  })

  it('accepts iteration counts from 600,000 to 5,000,000 and a 16-byte salt', async () => {
    for (const iterations of [599_999, 5_000_001, 1.5]) {
      await expect(deriveThreadKey('pw', { ...params, iterations })).rejects.toThrow(
        code('malformed'),
      )
    }
    await expect(deriveThreadKey('pw', { ...params, salt: new Uint8Array(15) })).rejects.toThrow(
      code('malformed'),
    )
    for (const iterations of [600_000, 5_000_000]) {
      await deriveThreadKey('pw', { ...params, iterations })
    }
  }, 60_000)
})

interface ProtectedVectorFile {
  spec: string
  description: string
  threads: {
    name: string
    password: string
    salt: string
    iterations: number
    thread_key: string
    verifier: string
    message_key: string
    wrap_nonce: string
    wrapped_key: string
  }[]
}

async function buildVectorFile(): Promise<ProtectedVectorFile> {
  const file: ProtectedVectorFile = {
    spec: 'spec/protected-mail.md',
    description:
      'Password-protected mail vectors. Each thread lists its password, salt and iteration count, the ' +
      'thread key and verifier they derive with PBKDF2-HMAC-SHA256, and a message key wrapped under the thread ' +
      'key with the listed nonce. An implementation must derive the same values and produce the same bytes.',
    threads: [],
  }
  for (const iterations of [600_000, 1_200_000]) {
    const name = `${iterations} iterations`
    const threadParams = { salt: testBytes(`${name} salt`, 16), iterations }
    const password = 'correct horse battery staple'
    const { threadKey, verifier } = await deriveThreadKey(password, threadParams)
    const messageKey = testBytes(`${name} message key`, 32)
    const wrapNonce = testBytes(`${name} wrap nonce`, 12)
    const wrapped = await sealProtectedKeyWithRandomness(threadKey, messageKey, {
      nonce: () => wrapNonce,
    })
    file.threads.push({
      name,
      password,
      salt: hex(threadParams.salt),
      iterations,
      thread_key: hex(
        new Uint8Array(pbkdf2Sync(utf8(password), threadParams.salt, iterations, 32, 'sha256')),
      ),
      verifier,
      message_key: hex(messageKey),
      wrap_nonce: hex(wrapNonce),
      wrapped_key: hex(wrapped),
    })
  }
  return file
}

describe('password-protected mail vectors', () => {
  it('match this implementation', async () => {
    const built = await buildVectorFile()
    const path = fileURLToPath(new URL('../../test-vectors/protected-mail.json', import.meta.url))
    if (process.env.UPDATE_VECTORS === '1') {
      writeFileSync(path, JSON.stringify(built, null, 2) + '\n')
    }
    const stored = readVectors<ProtectedVectorFile>('protected-mail.json')
    expect(built).toEqual(stored)
  }, 300_000)

  it('open with the library and agree with node:crypto', async () => {
    const stored = readVectors<ProtectedVectorFile>('protected-mail.json')
    for (const t of stored.threads) {
      const { threadKey, verifier } = await deriveThreadKey(t.password, {
        salt: fromHex(t.salt),
        iterations: t.iterations,
      })
      expect(verifier).toBe(t.verifier)
      expect(hex(sha256(fromHex(t.thread_key)))).toBe(t.verifier)
      expect(hex(await openProtectedKey(threadKey, fromHex(t.wrapped_key)))).toBe(t.message_key)
      const w = fromHex(t.wrapped_key)
      expect(
        hex(
          nodeGcmOpen(fromHex(t.thread_key), w.subarray(0, 12), w.subarray(12), new Uint8Array(0)),
        ),
      ).toBe(t.message_key)
    }
  }, 300_000)
})
