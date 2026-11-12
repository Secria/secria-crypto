// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest'
import { generateKeySet } from '../src/account.js'
import { hex, utf8 } from '../src/bytes.js'
import {
  openBody,
  openSelfWrap,
  openWrap,
  sealBody,
  sealSelfWrap,
  sealSelfWrapWithRandomness,
  sealWrap,
  sealWrapWithRandomness,
} from '../src/mail.js'
import { fromHex, keySetFromSeed, readVectors } from './helpers.js'

interface VectorFile {
  bodies: {
    name: string
    key: string
    plaintext: string
    blob: string
    format: 1 | 2
    opens_in_v2_only_mode: boolean
  }[]
  invalid_bodies: { name: string; key: string; blob: string }[]
  wraps: {
    name: string
    recipient_x25519_private: string
    recipient_mlkem_seed: string
    sender_x25519_public: string
    sender_x25519_private: string
    key: string
    encapsulation_seed: string
    salt: string
    nonce: string
    kem_ciphertext: string
    wrapped_key: string
  }[]
  self_wraps: {
    name: string
    self_key: string
    key: string
    salt: string
    nonce: string
    wrapped_key: string
  }[]
}

const vectors = readVectors<VectorFile>('mail.json')

describe('mail vectors', () => {
  for (const v of vectors.bodies) {
    it(`opens the body "${v.name}"`, async () => {
      const body = await openBody(fromHex(v.key), fromHex(v.blob), 'auto')
      expect(hex(body.plaintext)).toBe(v.plaintext)
      expect(body.format).toBe(v.format)
      const strict = openBody(fromHex(v.key), fromHex(v.blob), 'v2-only')
      if (v.opens_in_v2_only_mode) await expect(strict).resolves.toBeDefined()
      else await expect(strict).rejects.toThrow()
    })
  }
  it('opens the blob it was given when the call began', async () => {
    const key = new Uint8Array(32).fill(7)
    const blob = await sealBody(key, utf8('first!'))
    const other = await sealBody(key, utf8('second'))
    const pending = openBody(key, blob, 'v2-only')
    blob.set(other)
    expect((await pending).plaintext).toEqual(utf8('first!'))
  })
  for (const v of vectors.invalid_bodies) {
    it(`rejects the body "${v.name}"`, async () => {
      await expect(openBody(fromHex(v.key), fromHex(v.blob), 'auto')).rejects.toThrow()
      await expect(openBody(fromHex(v.key), fromHex(v.blob), 'v2-only')).rejects.toThrow()
    })
  }
  for (const v of vectors.wraps) {
    it(`reproduces and opens the wrap "${v.name}"`, async () => {
      const recipient = keySetFromSeed(
        fromHex(v.recipient_x25519_private),
        fromHex(v.recipient_mlkem_seed),
      )
      const wrap = await sealWrapWithRandomness(
        fromHex(v.sender_x25519_private),
        recipient.publicKey,
        fromHex(v.key),
        {
          salt: fromHex(v.salt),
          nonce: fromHex(v.nonce),
          encapsulationSeed: fromHex(v.encapsulation_seed),
        },
      )
      expect(hex(wrap.kemCiphertext)).toBe(v.kem_ciphertext)
      expect(hex(wrap.wrappedKey)).toBe(v.wrapped_key)
      const key = await openWrap(recipient, fromHex(v.sender_x25519_public), {
        kemCiphertext: fromHex(v.kem_ciphertext),
        salt: fromHex(v.salt),
        wrappedKey: fromHex(v.wrapped_key),
      })
      expect(hex(key)).toBe(v.key)
    })
  }
  for (const v of vectors.self_wraps) {
    it(`reproduces and opens the self wrap "${v.name}"`, async () => {
      const wrap = await sealSelfWrapWithRandomness(fromHex(v.self_key), fromHex(v.key), {
        salt: fromHex(v.salt),
        nonce: fromHex(v.nonce),
      })
      expect(hex(wrap.wrappedKey)).toBe(v.wrapped_key)
      expect(hex(await openSelfWrap(fromHex(v.self_key), wrap))).toBe(v.key)
    })
  }
})

describe('sealing', () => {
  // A string, an array-like and a plain object of the right length must not
  // be read as bytes: a numeric string or { length: 32 } would otherwise
  // become 32 zero bytes, and a string body an empty one.
  const notBytes = [
    '1'.repeat(32),
    { length: 32 },
    Array(32).fill(1),
    {},
  ] as unknown as Uint8Array[]
  const key = new Uint8Array(32).fill(9)

  it('refuses keys and plaintexts that are not Uint8Arrays', async () => {
    const recipient = await generateKeySet()
    const sender = new Uint8Array(32).fill(3)
    for (const bad of notBytes) {
      await expect(sealBody(bad, utf8('body'))).rejects.toThrow()
      await expect(sealBody(key, bad)).rejects.toThrow()
      await expect(sealWrap(bad, recipient.publicKey, key)).rejects.toThrow()
      await expect(sealWrap(sender, recipient.publicKey, bad)).rejects.toThrow()
      await expect(sealWrap(sender, { ...recipient.publicKey, x25519: bad }, key)).rejects.toThrow()
      await expect(sealWrap(sender, { ...recipient.publicKey, mlkem: bad }, key)).rejects.toThrow()
      await expect(sealSelfWrap(bad, key)).rejects.toThrow()
      await expect(sealSelfWrap(recipient.selfKey, bad)).rejects.toThrow()
      await expect(openBody(bad, new Uint8Array(29), 'v2-only')).rejects.toThrow()
    }
  })

  it('requires a mode for opening a body', async () => {
    const blob = await sealBody(key, utf8('body'))
    for (const mode of [undefined, '', 'v2', 'AUTO']) {
      await expect(openBody(key, blob, mode as 'auto')).rejects.toThrow(RangeError)
    }
  })
})
