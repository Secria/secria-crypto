// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

/** Deliberately coarse: `authentication` covers every failed tag check. */
export type CryptoErrorCode = 'malformed' | 'authentication'

export class CryptoError extends Error {
  override readonly name = 'CryptoError'

  constructor(
    readonly code: CryptoErrorCode,
    message: string,
  ) {
    super(message)
  }
}

export function malformed(what: string): CryptoError {
  return new CryptoError('malformed', `malformed input: ${what}`)
}

export function authenticationFailed(): CryptoError {
  return new CryptoError('authentication', 'failed authentication')
}
