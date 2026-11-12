// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { describe, expect, it } from 'vitest'
import {
  deriveLoginHash,
  deriveLoginHashV1,
  deriveVaultKey,
  deriveVaultKeyV1,
  openArchivedKeySet,
  parsePublicKeySet,
  unwrapKeySet,
} from '../src/account.js'
import { hex } from '../src/bytes.js'
import { openBody, openSelfWrap, openWrap } from '../src/mail.js'
import {
  deriveRecoveryKey,
  entropyToPhrase,
  phraseToEntropy,
  recoveryProof,
} from '../src/recovery.js'
import { deriveThreadKey, openProtectedKey } from '../src/protected.js'
import { fromHex, keySetFromSeed, readVectors } from './helpers.js'

interface Wrapped {
  x25519: string
  mlkem1024: string
  self: string
}

interface DeployedVectors {
  password_derivation: {
    address: string
    password: string
    login_hash: string
    vault_key: string
  }[]
  password_derivation_v1: {
    address: string
    password: string
    login_hash: string
    vault_key: string
  }[]
  vaults: {
    vault_key: string
    key_id: string
    x25519_public: string
    mlkem_public: string
    wrapped: Wrapped
    expected_x25519_private: string
    expected_self_key: string
  }[]
  messages: {
    name: string
    recipient_x25519_private: string
    recipient_mlkem_seed: string
    sender_x25519_public: string
    kem_ciphertext: string
    salt: string
    wrapped_key: string
    key: string
    body_blob: string
    body: string
    sender_self_key: string
    self_salt: string
    self_wrapped_key: string
  }[]
  recovery: {
    entropy: string
    phrase: string[]
    recovery_key: string
    x25519_public: string
    mlkem_public: string
    wrapped: Wrapped
    expected_self_key: string
    proof: { ephemeral_public: string; token: string; proof: string }
  }
  archived_key_sets: {
    current_self_key: string
    archived_key_id: string
    sealed: string
    expected_x25519_private: string
    expected_self_key: string
  }[]
  protected_mail: {
    name: string
    password: string
    salt: string
    iterations: number
    verifier: string
    message_key: string
    wrapped_key: string
    body: string
    body_plaintext: string
    reply: string
    reply_text: string
  }[]
}

const deployed = readVectors<DeployedVectors>('deployed.json')
const unhex = (w: Wrapped) => ({
  x25519: fromHex(w.x25519),
  mlkem1024: fromHex(w.mlkem1024),
  self: fromHex(w.self),
})

describe('output of the deployed app code', () => {
  it('derives the same login hashes and vault keys', async () => {
    for (const v of deployed.password_derivation) {
      expect(await deriveLoginHash(v.address, v.password)).toBe(v.login_hash)
      expect(hex(await deriveVaultKey(v.address, v.password))).toBe(v.vault_key)
    }
    for (const v of deployed.password_derivation_v1) {
      expect(await deriveLoginHashV1(v.address, v.password)).toBe(v.login_hash)
      expect(hex(await deriveVaultKeyV1(v.address, v.password))).toBe(v.vault_key)
    }
  }, 120_000)

  it('opens vaults the app created', async () => {
    for (const v of deployed.vaults) {
      const publicKey = parsePublicKeySet(fromHex(v.x25519_public), fromHex(v.mlkem_public))
      expect(hex(publicKey.keyId)).toBe(v.key_id)
      const keys = await unwrapKeySet(fromHex(v.vault_key), unhex(v.wrapped), publicKey)
      expect(hex(keys.x25519)).toBe(v.expected_x25519_private)
      expect(hex(keys.selfKey)).toBe(v.expected_self_key)
    }
  }, 120_000)

  it('opens a message the app sent, as the recipient and as the sender', async () => {
    for (const m of deployed.messages) {
      const recipient = keySetFromSeed(
        fromHex(m.recipient_x25519_private),
        fromHex(m.recipient_mlkem_seed),
      )
      const key = await openWrap(recipient, fromHex(m.sender_x25519_public), {
        kemCiphertext: fromHex(m.kem_ciphertext),
        salt: fromHex(m.salt),
        wrappedKey: fromHex(m.wrapped_key),
      })
      expect(hex(key)).toBe(m.key)
      const body = await openBody(key, fromHex(m.body_blob), 'v2-only')
      expect(hex(body.plaintext)).toBe(m.body)
      const selfKey = await openSelfWrap(fromHex(m.sender_self_key), {
        salt: fromHex(m.self_salt),
        wrappedKey: fromHex(m.self_wrapped_key),
      })
      expect(hex(selfKey)).toBe(m.key)
    }
  })

  it('reads the app recovery phrase, key, wraps and proof', async () => {
    const r = deployed.recovery
    expect(hex(phraseToEntropy(r.phrase))).toBe(r.entropy)
    expect(entropyToPhrase(fromHex(r.entropy))).toEqual(r.phrase)
    const recoveryKey = deriveRecoveryKey(fromHex(r.entropy))
    expect(hex(recoveryKey)).toBe(r.recovery_key)
    const publicKey = parsePublicKeySet(fromHex(r.x25519_public), fromHex(r.mlkem_public))
    const keys = await unwrapKeySet(recoveryKey, unhex(r.wrapped), publicKey)
    expect(hex(keys.selfKey)).toBe(r.expected_self_key)
    expect(hex(recoveryProof(keys.x25519, fromHex(r.proof.ephemeral_public), r.proof.token))).toBe(
      r.proof.proof,
    )
  })

  it('opens key sets the app archived', async () => {
    for (const a of deployed.archived_key_sets) {
      const keys = await openArchivedKeySet(
        fromHex(a.current_self_key),
        fromHex(a.archived_key_id),
        fromHex(a.sealed),
      )
      expect(hex(keys.x25519)).toBe(a.expected_x25519_private)
      expect(hex(keys.selfKey)).toBe(a.expected_self_key)
    }
  })

  it('opens protected mail as the app writes it today', async () => {
    for (const m of deployed.protected_mail) {
      const { threadKey, verifier } = await deriveThreadKey(m.password, {
        salt: fromHex(m.salt),
        iterations: m.iterations,
      })
      expect(verifier).toBe(m.verifier)
      const key = await openProtectedKey(threadKey, fromHex(m.wrapped_key))
      expect(hex(key)).toBe(m.message_key)
      expect(hex((await openBody(key, fromHex(m.body), 'v2-only')).plaintext)).toBe(
        m.body_plaintext,
      )
      const reply = await openBody(key, fromHex(m.reply), 'v2-only')
      expect(new TextDecoder().decode(reply.plaintext)).toBe(m.reply_text)
    }
  }, 120_000)
})
