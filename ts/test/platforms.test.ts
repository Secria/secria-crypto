// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest'
import {
  checkKeySet,
  deriveLoginHashV1,
  deriveVaultKeyV1,
  parsePublicKeySet,
  unwrapKeySet,
  type PrivateKeyParts,
} from '../src/account.js'
import { hex } from '../src/bytes.js'
import { openBody, openWrap, sealWrap } from '../src/mail.js'
import {
  checkDecapsulationKey,
  checkEncapsulationKey,
  decapsulate,
  encapsulate,
} from '../src/mlkem.js'
import { randomBytes, x25519PublicKey } from '../src/primitives.js'
import {
  deriveRecoveryKey,
  entropyToPhrase,
  phraseToEntropy,
  recoveryProof,
} from '../src/recovery.js'
import { fromHex, keyPairFromSeed, readVectors } from './helpers.js'

interface Wrapped {
  x25519: string
  mlkem1024: string
  self: string
}

interface KeySetEntry {
  name: string
  key_id: string
  x25519_public: string
  mlkem_public: string
  expected_x25519_private: string
  expected_mlkem_private?: string
  expected_self_key: string
  wrapped: Wrapped
}

interface PlatformVectors {
  password_derivation_v1: {
    address: string
    password: string
    login_hash: string
    vault_key: string
    source: string
  }[]
  vaults: (KeySetEntry & { vault_key: string })[]
  recovery: (KeySetEntry & {
    entropy: string
    phrase: string[]
    recovery_key: string
    proof?: { ephemeral_public: string; token: string; proof: string }
  })[]
  platform_unwraps: {
    name: string
    key_id: string
    x25519_public: string
    mlkem_public: string
    x25519_private: string
    mlkem_private: string
    self_key: string
    expected_x25519_private: string
    expected_mlkem_private?: string
    expected_self_key: string
  }[]
  inbound_messages: {
    name: string
    sender_x25519_public: string
    key: string
    body_blob: string
    body: string
    attachment_blob: string
    attachment: string
    recipients: {
      address: string
      recipient_x25519_private: string
      recipient_mlkem_seed: string
      x25519_public: string
      mlkem_public: string
      key_id: string
      key_used: string
      kem_ciphertext: string
      salt: string
      wrapped_key: string
    }[]
  }[]
}

const platforms = readVectors<PlatformVectors>('deployed-platforms.json')
const unhexWrapped = (w: Wrapped) => ({
  x25519: fromHex(w.x25519),
  mlkem1024: fromHex(w.mlkem1024),
  self: fromHex(w.self),
})

/** The key-set checks of account.md section 1, then an ML-KEM and a wrap round trip through the keys. */
async function expectUsableKeySet(parts: PrivateKeyParts, e: KeySetEntry) {
  const ek = fromHex(e.mlkem_public)
  checkEncapsulationKey(ek)
  expect(hex(checkDecapsulationKey(parts.mlkem))).toBe(e.mlkem_public)
  const keys = checkKeySet(parts, fromHex(e.x25519_public), ek, fromHex(e.key_id))
  const enc = encapsulate(ek)
  expect(decapsulate(enc.ciphertext, keys.mlkem)).toEqual(enc.sharedKey)
  const sender = randomBytes(32)
  const k = randomBytes(32)
  const wrap = await sealWrap(sender, keys.publicKey, k)
  expect(await openWrap(keys, x25519PublicKey(sender), wrap)).toEqual(k)
}

describe('output of the VPN apps and the mail server', () => {
  it('derives the login hash and vault key the VPN apps derive', async () => {
    for (const d of platforms.password_derivation_v1) {
      expect(await deriveLoginHashV1(d.address, d.password)).toBe(d.login_hash)
      expect(hex(await deriveVaultKeyV1(d.address, d.password))).toBe(d.vault_key)
    }
  }, 120_000)

  for (const e of platforms.vaults) {
    it(`opens the vault and accepts the key set: ${e.name}`, async () => {
      const pub = parsePublicKeySet(fromHex(e.x25519_public), fromHex(e.mlkem_public))
      expect(hex(pub.keyId)).toBe(e.key_id)
      const keys = await unwrapKeySet(fromHex(e.vault_key), unhexWrapped(e.wrapped), pub)
      expect(hex(keys.x25519)).toBe(e.expected_x25519_private)
      expect(hex(keys.selfKey)).toBe(e.expected_self_key)
      if (e.expected_mlkem_private) expect(hex(keys.mlkem)).toBe(e.expected_mlkem_private)
      await expectUsableKeySet(keys, e)
    }, 60_000)
  }

  for (const r of platforms.recovery) {
    it(`reads the recovery phrase, key and wraps: ${r.name}`, async () => {
      expect(hex(phraseToEntropy(r.phrase))).toBe(r.entropy)
      expect(entropyToPhrase(fromHex(r.entropy))).toEqual(r.phrase)
      const recoveryKey = deriveRecoveryKey(fromHex(r.entropy))
      expect(hex(recoveryKey)).toBe(r.recovery_key)
      const pub = parsePublicKeySet(fromHex(r.x25519_public), fromHex(r.mlkem_public))
      expect(hex(pub.keyId)).toBe(r.key_id)
      const keys = await unwrapKeySet(recoveryKey, unhexWrapped(r.wrapped), pub)
      expect(hex(keys.x25519)).toBe(r.expected_x25519_private)
      expect(hex(keys.selfKey)).toBe(r.expected_self_key)
      if (r.expected_mlkem_private) expect(hex(keys.mlkem)).toBe(r.expected_mlkem_private)
      if (r.proof) {
        expect(
          hex(recoveryProof(keys.x25519, fromHex(r.proof.ephemeral_public), r.proof.token)),
        ).toBe(r.proof.proof)
      }
    })
  }

  for (const u of platforms.platform_unwraps) {
    it(`agrees with the app's own unwrap: ${u.name}`, () => {
      expect(u.x25519_private).toBe(u.expected_x25519_private)
      expect(u.self_key).toBe(u.expected_self_key)
      if (u.expected_mlkem_private) expect(u.mlkem_private).toBe(u.expected_mlkem_private)
      checkKeySet(
        {
          x25519: fromHex(u.x25519_private),
          mlkem: fromHex(u.mlkem_private),
          selfKey: fromHex(u.self_key),
        },
        fromHex(u.x25519_public),
        fromHex(u.mlkem_public),
        fromHex(u.key_id),
      )
    })
  }

  for (const m of platforms.inbound_messages) {
    for (const r of m.recipients) {
      it(`opens mail the mail server sealed for ${r.address}`, async () => {
        const kem = keyPairFromSeed(fromHex(r.recipient_mlkem_seed))
        const x = fromHex(r.recipient_x25519_private)
        expect(hex(x25519PublicKey(x))).toBe(r.x25519_public)
        expect(hex(kem.encapsulationKey)).toBe(r.mlkem_public)
        const keys = checkKeySet(
          { x25519: x, mlkem: kem.decapsulationKey, selfKey: new Uint8Array(32).fill(7) },
          x25519PublicKey(x),
          kem.encapsulationKey,
          fromHex(r.key_id),
        )
        expect(hex(keys.publicKey.keyId)).toBe(r.key_id)
        expect(r.key_used).toBe(r.key_id)
        const key = await openWrap(keys, fromHex(m.sender_x25519_public), {
          kemCiphertext: fromHex(r.kem_ciphertext),
          salt: fromHex(r.salt),
          wrappedKey: fromHex(r.wrapped_key),
        })
        expect(hex(key)).toBe(m.key)
        for (const [blob, want] of [
          [m.body_blob, m.body],
          [m.attachment_blob, m.attachment],
        ] as const) {
          for (const mode of ['v2-only', 'auto'] as const) {
            const out = await openBody(key, fromHex(blob), mode)
            expect(hex(out.plaintext)).toBe(want)
            expect(out.format).toBe(2)
          }
        }
      })
    }
  }
})
