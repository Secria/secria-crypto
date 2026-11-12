// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { argon2dAsync, argon2idAsync } from '@noble/hashes/argon2.js'
import { sha1 } from '@noble/hashes/legacy.js'
import { base64, concat, constantTimeEqual, copyBytes, hex, utf8 } from './bytes.js'
import { CryptoError, malformed } from './errors.js'
import {
  checkDecapsulationKey,
  checkEncapsulationKey,
  generateKeyPair,
  MLKEM_DECAPSULATION_KEY_SIZE,
} from './mlkem.js'
import {
  aesGcmOpen,
  aesGcmSeal,
  hkdf32,
  NONCE_SIZE,
  randomBytes,
  sha256,
  TAG_SIZE,
  X25519_KEY_SIZE,
  x25519PublicKey,
} from './primitives.js'

export const SELF_KEY_SIZE = 32
export const KEY_ID_SIZE = 32

export interface PublicKeySet {
  readonly x25519: Uint8Array
  readonly mlkem: Uint8Array
  readonly keyId: Uint8Array
}

/** The private keys are not enumerable: JSON, logs and spreads show only the public keys. */
export interface PrivateKeySet {
  readonly x25519: Uint8Array
  /** The 3168-byte FIPS 203 decapsulation key. */
  readonly mlkem: Uint8Array
  readonly selfKey: Uint8Array
  readonly publicKey: PublicKeySet
}

export function keyId(x25519Public: Uint8Array, mlkemPublic: Uint8Array): Uint8Array {
  return sha256(
    concat(
      copyBytes(x25519Public, 'X25519 public key'),
      copyBytes(mlkemPublic, 'ML-KEM public key'),
    ),
  )
}

export function parsePublicKeySet(x25519Public: Uint8Array, mlkemPublic: Uint8Array): PublicKeySet {
  const x25519 = copyBytes(x25519Public, 'X25519 public key')
  const mlkem = copyBytes(mlkemPublic, 'ML-KEM public key')
  if (x25519.length !== X25519_KEY_SIZE) throw malformed('X25519 public key length')
  checkEncapsulationKey(mlkem)
  return { x25519, mlkem, keyId: keyId(x25519, mlkem) }
}

const checkedKeySets = new WeakMap<PrivateKeySet, PrivateKeySet>()

const INSPECT = Symbol.for('nodejs.util.inspect.custom')

function keySet(
  x25519: Uint8Array,
  mlkem: Uint8Array,
  selfKey: Uint8Array,
  publicKey: PublicKeySet,
): PrivateKeySet {
  const describe = () => ({ keyId: hex(publicKey.keyId) })
  const set = Object.defineProperties(
    { publicKey },
    {
      x25519: { value: x25519 },
      mlkem: { value: mlkem },
      selfKey: { value: selfKey },
      toJSON: { value: describe },
      [INSPECT]: { value: () => `PrivateKeySet ${JSON.stringify(describe())}` },
    },
  )
  return Object.freeze(set) as PrivateKeySet
}

export interface PrivateKeyParts {
  x25519: Uint8Array
  mlkem: Uint8Array
  selfKey: Uint8Array
}

/** A caller with no stored identifier yet passes `keyId(x25519Public, mlkemPublic)`. */
export function checkKeySet(
  privateKeys: PrivateKeyParts,
  x25519Public: Uint8Array,
  mlkemPublic: Uint8Array,
  storedKeyId: Uint8Array,
): PrivateKeySet {
  const publicKey = parsePublicKeySet(x25519Public, mlkemPublic)
  const x25519 = copyBytes(privateKeys.x25519, 'X25519 private key')
  const mlkem = copyBytes(privateKeys.mlkem, 'ML-KEM private key')
  const selfKey = copyBytes(privateKeys.selfKey, 'self key')
  if (!constantTimeEqual(x25519PublicKey(x25519), publicKey.x25519)) {
    throw malformed('X25519 private key does not match the public key')
  }
  const embedded = checkDecapsulationKey(mlkem)
  if (!constantTimeEqual(embedded, publicKey.mlkem)) {
    throw malformed('ML-KEM-1024 private key does not match the public key')
  }
  if (selfKey.length !== SELF_KEY_SIZE) throw malformed('self key length')
  if (constantTimeEqual(selfKey, x25519)) {
    throw malformed('self key equals the X25519 private key')
  }
  if (!constantTimeEqual(copyBytes(storedKeyId, 'key identifier'), publicKey.keyId)) {
    throw malformed('key identifier does not match the public keys')
  }
  const checked = keySet(x25519, mlkem, selfKey, publicKey)
  checkedKeySets.set(
    checked,
    keySet(Uint8Array.from(x25519), Uint8Array.from(mlkem), Uint8Array.from(selfKey), {
      x25519: Uint8Array.from(publicKey.x25519),
      mlkem: Uint8Array.from(publicKey.mlkem),
      keyId: Uint8Array.from(publicKey.keyId),
    }),
  )
  return checked
}

export function checkedKeySet(keys: PrivateKeySet): PrivateKeySet {
  const checked = typeof keys === 'object' && keys !== null ? checkedKeySets.get(keys) : undefined
  if (checked === undefined) throw malformed('key set was not checked with checkKeySet')
  return checked
}

export async function generateKeySet(): Promise<PrivateKeySet> {
  const x25519 = randomBytes(X25519_KEY_SIZE)
  const x25519Public = x25519PublicKey(x25519)
  const kem = generateKeyPair()
  return checkKeySet(
    { x25519, mlkem: kem.decapsulationKey, selfKey: randomBytes(SELF_KEY_SIZE) },
    x25519Public,
    kem.encapsulationKey,
    keyId(x25519Public, kem.encapsulationKey),
  )
}

export interface Argon2Params {
  type: 'argon2id' | 'argon2d'
  password: Uint8Array
  salt: Uint8Array
  iterations: number
  memoryKiB: number
  parallelism: number
  outputLength: number
}

/** The default is @noble/hashes; an application may pass a faster WebAssembly build. */
export type Argon2 = (params: Argon2Params) => Promise<Uint8Array>

export const nobleArgon2: Argon2 = (params) => {
  const opts = {
    t: params.iterations,
    m: params.memoryKiB,
    p: params.parallelism,
    dkLen: params.outputLength,
  }
  return params.type === 'argon2d'
    ? argon2dAsync(params.password, params.salt, opts)
    : argon2idAsync(params.password, params.salt, opts)
}

const ARGON2_ITERATIONS = 3
const ARGON2_MEMORY_KIB = 65536
const ARGON2_PARALLELISM = 1
const DERIVED_SIZE = 32
const LOGIN_HASH_V1_SIZE = 24

const CANONICAL_ADDRESS = /^[\x21-\x40\x5B-\x7E]+$/

// An address as the user typed it would derive keys that no other client can match.
function checkCanonicalAddress(address: string): void {
  if (typeof address !== 'string' || !CANONICAL_ADDRESS.test(address)) {
    throw malformed('address is not in canonical form')
  }
}

async function derive(
  saltInput: string,
  password: string,
  argon2: Argon2,
  v1 = false,
  outputLength = DERIVED_SIZE,
): Promise<Uint8Array> {
  const digest = v1 ? sha1(utf8(saltInput)) : sha256(utf8(saltInput))
  const out = await argon2({
    type: v1 ? 'argon2d' : 'argon2id',
    password: utf8(password),
    salt: utf8(base64(digest)),
    iterations: ARGON2_ITERATIONS,
    memoryKiB: ARGON2_MEMORY_KIB,
    parallelism: ARGON2_PARALLELISM,
    outputLength,
  })
  if (!(out instanceof Uint8Array) || out.length !== outputLength) {
    throw malformed('Argon2 output length')
  }
  return out
}

export async function deriveLoginHash(
  address: string,
  password: string,
  argon2: Argon2 = nobleArgon2,
): Promise<string> {
  checkCanonicalAddress(address)
  return hex(await derive(address, password, argon2))
}

/** The vault key never leaves the client; only the login hash is sent. */
export async function deriveVaultKey(
  address: string,
  password: string,
  argon2: Argon2 = nobleArgon2,
): Promise<Uint8Array> {
  checkCanonicalAddress(address)
  return derive('vault' + address, password, argon2)
}

export async function deriveLoginHashV1(
  address: string,
  password: string,
  argon2: Argon2 = nobleArgon2,
): Promise<string> {
  checkCanonicalAddress(address)
  return hex(await derive(address, password, argon2, true, LOGIN_HASH_V1_SIZE))
}

export async function deriveVaultKeyV1(
  address: string,
  password: string,
  argon2: Argon2 = nobleArgon2,
): Promise<Uint8Array> {
  checkCanonicalAddress(address)
  return derive('vault' + address, password, argon2, true)
}

type KeySlot = 'x25519' | 'mlkem1024' | 'self'

const SLOT_SIZES: Record<KeySlot, number> = {
  x25519: X25519_KEY_SIZE,
  mlkem1024: MLKEM_DECAPSULATION_KEY_SIZE,
  self: SELF_KEY_SIZE,
}

export interface WrappedKeySet {
  x25519: Uint8Array
  mlkem1024: Uint8Array
  self: Uint8Array
}

// Checked so that nothing its reader would refuse is written, and copied so
// that the caller cannot change the buffers during the call.
function checkedForWriting(keys: PrivateKeySet): PrivateKeySet {
  return checkKeySet(
    { x25519: keys.x25519, mlkem: keys.mlkem, selfKey: keys.selfKey },
    keys.publicKey.x25519,
    keys.publicKey.mlkem,
    keys.publicKey.keyId,
  )
}

function copyWrapped(w: WrappedKeySet): WrappedKeySet {
  return {
    x25519: copyBytes(w.x25519, 'wrapped X25519 key'),
    mlkem1024: copyBytes(w.mlkem1024, 'wrapped ML-KEM key'),
    self: copyBytes(w.self, 'wrapped self key'),
  }
}

function copyPublicKey(p: PublicKeySet): PublicKeySet {
  return {
    x25519: copyBytes(p.x25519, 'X25519 public key'),
    mlkem: copyBytes(p.mlkem, 'ML-KEM public key'),
    keyId: copyBytes(p.keyId, 'key identifier'),
  }
}

// Keys that decrypt but fail the checks were altered in storage.
function asAuthentication<T>(check: () => T): T {
  try {
    return check()
  } catch (e) {
    if (e instanceof CryptoError) {
      throw new CryptoError('authentication', 'unwrapped keys do not match the stored public keys')
    }
    throw e
  }
}

function checkUnwrapped(parts: PrivateKeyParts, publicKey: PublicKeySet): PrivateKeySet {
  return asAuthentication(() =>
    checkKeySet(parts, publicKey.x25519, publicKey.mlkem, publicKey.keyId),
  )
}

export async function wrapKeySet(
  wrappingKey: Uint8Array,
  keys: PrivateKeySet,
): Promise<WrappedKeySet> {
  const key = copyBytes(wrappingKey, 'wrapping key')
  const checked = checkedForWriting(keys)
  const seal = async (secret: Uint8Array) => {
    const nonce = randomBytes(NONCE_SIZE)
    return concat(nonce, await aesGcmSeal(key, nonce, secret, new Uint8Array(0)))
  }
  return {
    x25519: await seal(checked.x25519),
    mlkem1024: await seal(checked.mlkem),
    self: await seal(checked.selfKey),
  }
}

/** The checks against the public keys detect a server swapping two wraps of equal length. */
export async function unwrapKeySet(
  wrappingKey: Uint8Array,
  wrapped: WrappedKeySet,
  publicKey: PublicKeySet,
): Promise<PrivateKeySet> {
  const key = copyBytes(wrappingKey, 'wrapping key')
  const stored = copyWrapped(wrapped)
  const pub = copyPublicKey(publicKey)
  const open = async (slot: KeySlot, w: Uint8Array) => {
    if (w.length !== NONCE_SIZE + SLOT_SIZES[slot] + TAG_SIZE) {
      throw malformed(`${slot} wrap`)
    }
    return aesGcmOpen(key, w.subarray(0, NONCE_SIZE), w.subarray(NONCE_SIZE), new Uint8Array(0))
  }
  const parts = {
    x25519: await open('x25519', stored.x25519),
    mlkem: await open('mlkem1024', stored.mlkem1024),
    selfKey: await open('self', stored.self),
  }
  return checkUnwrapped(parts, pub)
}

const ARCHIVE_SALT = utf8('secria-archived-keys')
const ARCHIVE_INFO = utf8('seal')
const ARCHIVED_SIZE = X25519_KEY_SIZE + MLKEM_DECAPSULATION_KEY_SIZE + SELF_KEY_SIZE

/** Keeps mail wrapped to an earlier key set readable after the keys change. */
export async function sealArchivedKeySet(
  currentSelfKey: Uint8Array,
  archived: PrivateKeySet,
): Promise<Uint8Array> {
  const selfKey = copyBytes(currentSelfKey, 'self key')
  if (selfKey.length !== SELF_KEY_SIZE) throw malformed('self key length')
  const keys = checkedForWriting(archived)
  const id = keys.publicKey.keyId
  const key = hkdf32(ARCHIVE_SALT, selfKey, ARCHIVE_INFO)
  const nonce = randomBytes(NONCE_SIZE)
  const plaintext = concat(keys.x25519, keys.mlkem, keys.selfKey)
  return concat(nonce, await aesGcmSeal(key, nonce, plaintext, utf8(base64(id))))
}

export async function openArchivedKeySet(
  currentSelfKey: Uint8Array,
  archivedKeyId: Uint8Array,
  sealed: Uint8Array,
): Promise<PrivateKeySet> {
  const selfKey = copyBytes(currentSelfKey, 'self key')
  const id = copyBytes(archivedKeyId, 'key identifier')
  if (selfKey.length !== SELF_KEY_SIZE) throw malformed('self key length')
  if (id.length !== KEY_ID_SIZE) throw malformed('key identifier length')
  const data = copyBytes(sealed, 'archived key set')
  if (data.length !== NONCE_SIZE + ARCHIVED_SIZE + TAG_SIZE) {
    throw malformed('archived key set length')
  }
  const key = hkdf32(ARCHIVE_SALT, selfKey, ARCHIVE_INFO)
  const plaintext = await aesGcmOpen(
    key,
    data.subarray(0, NONCE_SIZE),
    data.subarray(NONCE_SIZE),
    utf8(base64(id)),
  )
  const parts = {
    x25519: plaintext.subarray(0, X25519_KEY_SIZE),
    mlkem: plaintext.subarray(X25519_KEY_SIZE, X25519_KEY_SIZE + MLKEM_DECAPSULATION_KEY_SIZE),
    selfKey: plaintext.subarray(X25519_KEY_SIZE + MLKEM_DECAPSULATION_KEY_SIZE),
  }
  const embeddedEK = asAuthentication(() => checkDecapsulationKey(parts.mlkem))
  return checkUnwrapped(parts, {
    x25519: x25519PublicKey(parts.x25519),
    mlkem: embeddedEK,
    keyId: id,
  })
}
