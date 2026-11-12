// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

export { CryptoError, type CryptoErrorCode } from './errors.js'

export {
  checkKeySet,
  deriveLoginHash,
  deriveLoginHashV1,
  deriveVaultKey,
  deriveVaultKeyV1,
  generateKeySet,
  keyId,
  nobleArgon2,
  openArchivedKeySet,
  parsePublicKeySet,
  sealArchivedKeySet,
  unwrapKeySet,
  wrapKeySet,
  KEY_ID_SIZE,
  SELF_KEY_SIZE,
  type Argon2,
  type Argon2Params,
  type PrivateKeyParts,
  type PrivateKeySet,
  type PublicKeySet,
  type WrappedKeySet,
} from './account.js'

export {
  deriveRecoveryKey,
  entropyToPhrase,
  generateRecoveryEntropy,
  phraseToEntropy,
  recoveryProof,
  RECOVERY_ENTROPY_SIZE,
  RECOVERY_WORDS,
} from './recovery.js'

export {
  openBody,
  openSelfWrap,
  openWrap,
  sealBody,
  sealSelfWrap,
  sealWrap,
  MESSAGE_KEY_SIZE,
  type BodyMode,
  type OpenedBody,
  type SelfWrap,
  type Wrap,
} from './mail.js'

export {
  deriveThreadKey,
  newThreadSalt,
  openProtectedKey,
  sealProtectedKey,
  THREAD_SALT_SIZE,
  type ThreadKey,
  type ThreadParams,
} from './protected.js'
