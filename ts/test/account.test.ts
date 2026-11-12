// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { inspect } from 'node:util'
import { fileURLToPath } from 'node:url'
import { argon2d, argon2id } from 'hash-wasm'
import { describe, expect, it } from 'vitest'
import {
  checkKeySet,
  deriveLoginHash,
  deriveLoginHashV1,
  deriveVaultKey,
  deriveVaultKeyV1,
  generateKeySet,
  openArchivedKeySet,
  parsePublicKeySet,
  sealArchivedKeySet,
  unwrapKeySet,
  wrapKeySet,
  type Argon2,
} from '../src/account.js'
import { hex, utf8 } from '../src/bytes.js'
import {
  deriveRecoveryKey,
  entropyToPhrase,
  phraseToEntropy,
  recoveryProof,
} from '../src/recovery.js'
import { x25519PublicKey } from '../src/primitives.js'
import { fromHex, keyParts, keySetFromSeed, readVectors } from './helpers.js'

/** hash-wasm, an independent Argon2id implementation, to cross-check @noble/hashes. */
const hashWasmArgon2: Argon2 = (p) =>
  (p.type === 'argon2d' ? argon2d : argon2id)({
    password: p.password,
    salt: p.salt,
    iterations: p.iterations,
    memorySize: p.memoryKiB,
    parallelism: p.parallelism,
    hashLength: p.outputLength,
    outputType: 'binary',
  })

const code = (c: string) => expect.objectContaining({ code: c })

interface AccountVectorFile {
  spec: string
  description: string
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
  key_set: {
    x25519_private: string
    mlkem_seed: string
    self_key: string
    x25519_public: string
    mlkem_public: string
    key_id: string
  }
  recovery: { entropy: string; phrase: string[]; recovery_key: string }[]
  recovery_proof: {
    ephemeral_private: string
    ephemeral_public: string
    token: string
    proof: string
  }
}

const PASSWORD_CASES: { address: string; password: string }[] = [
  { address: 'alice@example.com', password: 'correct horse battery staple' },
  { address: 'bob@example.com', password: 'pässwörd ✓ 🔑' },
]

// Cases from the BIP-39 reference vectors (github.com/trezor/python-mnemonic, vectors.json).
const BIP39_CASES = [
  [
    '00000000000000000000000000000000',
    'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  ],
  [
    '7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f',
    'legal winner thank year wave sausage worth useful legal winner thank yellow',
  ],
  [
    '80808080808080808080808080808080',
    'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
  ],
  ['ffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'],
  [
    '9e885d952ad362caeb4efe34a8e91bd2',
    'ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic',
  ],
] as const

const fixed = (seed: number, n: number) =>
  Uint8Array.from({ length: n }, (_, i) => (seed * 31 + i * 7) & 0xff)

async function buildVectorFile(): Promise<AccountVectorFile> {
  const password_derivation = []
  const password_derivation_v1 = []
  for (const c of PASSWORD_CASES) {
    password_derivation.push({
      ...c,
      login_hash: await deriveLoginHash(c.address, c.password),
      vault_key: hex(await deriveVaultKey(c.address, c.password)),
    })
    password_derivation_v1.push({
      ...c,
      login_hash: await deriveLoginHashV1(c.address, c.password),
      vault_key: hex(await deriveVaultKeyV1(c.address, c.password)),
    })
  }
  const keys = keySetFromSeed(fixed(1, 32), fixed(2, 64), fixed(3, 32))
  const ephemeral = fixed(9, 32)
  return {
    spec: 'spec/account.md',
    description:
      'Account key vectors. Password derivations use the parameters of spec/account.md section 2 and were ' +
      'cross-checked against a second Argon2 implementation; password_derivation_v1 is the version 1 ' +
      'derivation of section 2.1. The recovery proof uses the key set below. ' +
      'Recovery phrases follow BIP-39 with 128 bits of entropy.',
    password_derivation,
    password_derivation_v1,
    key_set: {
      x25519_private: hex(keys.x25519),
      mlkem_seed: hex(fixed(2, 64)),
      self_key: hex(keys.selfKey),
      x25519_public: hex(keys.publicKey.x25519),
      mlkem_public: hex(keys.publicKey.mlkem),
      key_id: hex(keys.publicKey.keyId),
    },
    recovery: BIP39_CASES.map(([entropy, phrase]) => ({
      entropy,
      phrase: phrase.split(' '),
      recovery_key: hex(deriveRecoveryKey(fromHex(entropy))),
    })),
    recovery_proof: {
      ephemeral_private: hex(ephemeral),
      ephemeral_public: hex(x25519PublicKey(ephemeral)),
      token: 'recovery-challenge-7c1e',
      proof: hex(recoveryProof(keys.x25519, x25519PublicKey(ephemeral), 'recovery-challenge-7c1e')),
    },
  }
}

describe('account vectors', () => {
  it('match this implementation', async () => {
    const built = await buildVectorFile()
    if (process.env.UPDATE_VECTORS === '1') {
      const path = fileURLToPath(new URL('../../test-vectors/account.json', import.meta.url))
      writeFileSync(path, JSON.stringify(built, null, 2) + '\n')
    }
    expect(built).toEqual(readVectors<AccountVectorFile>('account.json'))
  }, 300_000)

  it('agree with an independent Argon2id implementation', async () => {
    const stored = readVectors<AccountVectorFile>('account.json')
    for (const v of stored.password_derivation) {
      expect(await deriveLoginHash(v.address, v.password, hashWasmArgon2)).toBe(v.login_hash)
      expect(hex(await deriveVaultKey(v.address, v.password, hashWasmArgon2))).toBe(v.vault_key)
    }
    for (const v of stored.password_derivation_v1) {
      expect(await deriveLoginHashV1(v.address, v.password, hashWasmArgon2)).toBe(v.login_hash)
      expect(hex(await deriveVaultKeyV1(v.address, v.password, hashWasmArgon2))).toBe(v.vault_key)
    }
  }, 300_000)
})

describe('password derivation', () => {
  it('rejects a password that is not valid Unicode', async () => {
    await expect(deriveLoginHash('a@example.com', 'bad \uDC00')).rejects.toThrow(code('malformed'))
  })

  it('refuses Argon2 output of the wrong length', async () => {
    const short: Argon2 = async (p) => new Uint8Array(p.outputLength - 1)
    await expect(deriveVaultKey('a@example.com', 'x', short)).rejects.toThrow(code('malformed'))
    await expect(deriveLoginHash('a@example.com', 'x', short)).rejects.toThrow(code('malformed'))
  })

  it('refuses an address that is not canonical, and arguments that are not strings', async () => {
    const addresses = [
      'Alice@example.com',
      ' alice@example.com',
      'alice@example.com\n',
      'alice@bücher.example',
      '',
      undefined,
      null,
      7,
    ]
    for (const address of addresses) {
      await expect(deriveLoginHash(address as string, 'x')).rejects.toThrow(code('malformed'))
      await expect(deriveVaultKey(address as string, 'x')).rejects.toThrow(code('malformed'))
    }
    for (const password of [undefined, null, 7, utf8('x')]) {
      await expect(deriveVaultKey('a@example.com', password as unknown as string)).rejects.toThrow(
        code('malformed'),
      )
    }
  })
})

describe('key sets', () => {
  it('refuses private keys that do not match the public keys', async () => {
    const a = await generateKeySet()
    const b = await generateKeySet()
    const parts = { x25519: a.x25519, mlkem: a.mlkem, selfKey: a.selfKey }
    const id = a.publicKey.keyId
    expect(() => checkKeySet(parts, b.publicKey.x25519, a.publicKey.mlkem, id)).toThrow(
      code('malformed'),
    )
    expect(() => checkKeySet(parts, a.publicKey.x25519, b.publicKey.mlkem, id)).toThrow(
      code('malformed'),
    )
    expect(() =>
      checkKeySet(parts, a.publicKey.x25519, a.publicKey.mlkem, b.publicKey.keyId),
    ).toThrow(code('malformed'))
    const corrupted = Uint8Array.from(a.mlkem)
    corrupted[3104]! ^= 1 // the stored hash of the encapsulation key
    expect(() =>
      checkKeySet({ ...parts, mlkem: corrupted }, a.publicKey.x25519, a.publicKey.mlkem, id),
    ).toThrow(code('malformed'))
    expect(() =>
      checkKeySet(parts, a.publicKey.x25519, a.publicKey.mlkem, a.publicKey.keyId),
    ).not.toThrow()
    for (const wrong of [
      { ...parts, x25519: a.x25519.subarray(1) },
      { ...parts, mlkem: a.mlkem.subarray(1) },
      { ...parts, selfKey: a.selfKey.subarray(1) },
      { ...parts, selfKey: a.x25519 },
    ]) {
      expect(() => checkKeySet(wrong, a.publicKey.x25519, a.publicKey.mlkem, id)).toThrow(
        code('malformed'),
      )
    }
  })

  it('requires the stored key identifier', async () => {
    const a = await generateKeySet()
    const parts = { x25519: a.x25519, mlkem: a.mlkem, selfKey: a.selfKey }
    const omitted = undefined as unknown as Uint8Array
    expect(() => checkKeySet(parts, a.publicKey.x25519, a.publicKey.mlkem, omitted)).toThrow(
      code('malformed'),
    )
  })

  it('refuses a SHA-1 key identifier', async () => {
    const a = await generateKeySet()
    const parts = { x25519: a.x25519, mlkem: a.mlkem, selfKey: a.selfKey }
    const sha1Id = new Uint8Array(
      createHash('sha1').update(a.publicKey.x25519).update(a.publicKey.mlkem).digest(),
    )
    expect(() => checkKeySet(parts, a.publicKey.x25519, a.publicKey.mlkem, sha1Id)).toThrow(
      code('malformed'),
    )
    const sealed = await sealArchivedKeySet(a.selfKey, a)
    await expect(openArchivedKeySet(a.selfKey, sha1Id, sealed)).rejects.toThrow(code('malformed'))
  })

  it('keeps private keys out of JSON, inspection and object spread', async () => {
    const keys = await generateKeySet()
    const secrets = [keys.x25519, keys.mlkem, keys.selfKey]
    // A Uint8Array appears in JSON as {"0":…,"1":…} and in inspection as [ …, … ].
    const forms = secrets.flatMap((k) => [
      hex(k),
      JSON.stringify(k).slice(1, -1),
      Array.from(k.subarray(0, 8)).join(', '),
    ])
    const shown = [JSON.stringify(keys), JSON.stringify({ keys }), JSON.stringify({ ...keys })]
    for (const text of shown) {
      for (const form of forms) expect(text).not.toContain(form)
    }
    expect(Object.keys(keys)).toEqual(['publicKey'])
    expect(JSON.parse(JSON.stringify(keys))).toEqual({ keyId: hex(keys.publicKey.keyId) })
    expect(inspect(keys)).toBe(`PrivateKeySet {"keyId":"${hex(keys.publicKey.keyId)}"}`)
  })

  it('checks ML-KEM encapsulation keys as FIPS 203 section 7.2 requires', async () => {
    const keys = await generateKeySet()
    const bad = Uint8Array.from(keys.publicKey.mlkem)
    bad[0] = 0x01
    bad[1] = 0x0d // the first coefficient becomes 3329, which is not below q
    expect(() => parsePublicKeySet(keys.publicKey.x25519, bad)).toThrow(code('malformed'))
    expect(() => parsePublicKeySet(keys.publicKey.x25519, bad.subarray(1))).toThrow(
      code('malformed'),
    )
  })

  it('refuses to wrap a key set that fails the checks', async () => {
    const keys = await generateKeySet()
    const vaultKey = fixed(9, 32)
    const broken = { ...keyParts(keys), selfKey: keys.x25519 }
    await expect(wrapKeySet(vaultKey, broken)).rejects.toThrow(code('malformed'))
    await expect(sealArchivedKeySet(keys.selfKey, broken)).rejects.toThrow(code('malformed'))
  })

  it('wraps what it was given when the call began', async () => {
    const keys = await generateKeySet()
    const vaultKey = fixed(10, 32)
    const selfKey = Uint8Array.from(keys.selfKey)
    const pending = wrapKeySet(vaultKey, { ...keyParts(keys), selfKey })
    selfKey.fill(0)
    const wrapped = await pending
    expect(keyParts(await unwrapKeySet(vaultKey, wrapped, keys.publicKey))).toEqual(keyParts(keys))
  })

  it('archives an earlier key set under the current self key', async () => {
    const current = await generateKeySet()
    const earlier = await generateKeySet()
    const sealed = await sealArchivedKeySet(current.selfKey, earlier)
    const opened = await openArchivedKeySet(current.selfKey, earlier.publicKey.keyId, sealed)
    expect(keyParts(opened)).toEqual(keyParts(earlier))
    await expect(
      openArchivedKeySet(current.selfKey, current.publicKey.keyId, sealed),
    ).rejects.toThrow(code('authentication'))
    await expect(
      openArchivedKeySet(earlier.selfKey, earlier.publicKey.keyId, sealed),
    ).rejects.toThrow(code('authentication'))
    await expect(openArchivedKeySet(current.selfKey, new Uint8Array(21), sealed)).rejects.toThrow(
      code('malformed'),
    )
  })

  it('detects a server exchanging two wraps of equal length', async () => {
    const keys = await generateKeySet()
    const vaultKey = fixed(7, 32)
    const wrapped = await wrapKeySet(vaultKey, keys)
    expect(keyParts(await unwrapKeySet(vaultKey, wrapped, keys.publicKey))).toEqual(keyParts(keys))
    const swapped = { ...wrapped, x25519: wrapped.self, self: wrapped.x25519 }
    await expect(unwrapKeySet(vaultKey, swapped, keys.publicKey)).rejects.toThrow(
      code('authentication'),
    )
    const copied = { ...wrapped, self: wrapped.x25519 }
    await expect(unwrapKeySet(vaultKey, copied, keys.publicKey)).rejects.toThrow(
      code('authentication'),
    )
  })
})

describe('recovery phrases', () => {
  it('match the BIP-39 reference vectors in both directions', () => {
    for (const [entropy, phrase] of BIP39_CASES) {
      expect(entropyToPhrase(fromHex(entropy)).join(' ')).toBe(phrase)
      expect(hex(phraseToEntropy(phrase.split(' ')))).toBe(entropy)
    }
  })

  it('accepts surrounding white space and capitals, and rejects bad words and checksums', () => {
    const words = BIP39_CASES[1][1].split(' ')
    expect(hex(phraseToEntropy(words.map((w) => ` ${w.toUpperCase()} `)))).toBe(BIP39_CASES[1][0])
    expect(() => phraseToEntropy([...words.slice(0, 11), 'zebra'])).toThrow(code('malformed'))
    expect(() => phraseToEntropy([...words.slice(0, 11), 'notaword'])).toThrow(code('malformed'))
    expect(() => phraseToEntropy(words.slice(0, 11))).toThrow(code('malformed'))
  })

  it('proves possession the way the server checks it', async () => {
    const keys = await generateKeySet()
    const ephemeral = fixed(8, 32)
    const proof = recoveryProof(keys.x25519, x25519PublicKey(ephemeral), 'token')
    // The server computes the same value from its ephemeral key and the account's public key.
    expect(recoveryProof(ephemeral, keys.publicKey.x25519, 'token')).toEqual(proof)
    expect(() => recoveryProof(keys.x25519, new Uint8Array(32), 'token')).toThrow(code('malformed'))
    expect(() =>
      recoveryProof(keys.x25519, x25519PublicKey(ephemeral), undefined as unknown as string),
    ).toThrow(code('malformed'))
  })
})
