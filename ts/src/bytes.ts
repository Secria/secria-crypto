// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { malformed } from './errors.js'

export function copyBytes(b: Uint8Array, what: string): Uint8Array<ArrayBuffer> {
  if (!(b instanceof Uint8Array)) throw malformed(`${what} is not a Uint8Array`)
  // new Uint8Array copies; Buffer.prototype.slice would return a view.
  return new Uint8Array(b)
}

export function asciiLower(s: string): string {
  return s.replace(/[A-Z]/g, (c) => c.toLowerCase())
}

const utf8Encoder = new TextEncoder()

const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/

// TextEncoder would silently replace an unpaired surrogate with U+FFFD.
export function utf8(s: string): Uint8Array {
  if (typeof s !== 'string') throw malformed('not a string')
  if (UNPAIRED_SURROGATE.test(s)) throw malformed('string is not valid Unicode')
  return utf8Encoder.encode(s)
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  let length = 0
  for (const p of parts) length += p.length
  const out = new Uint8Array(length)
  let offset = 0
  for (const p of parts) {
    out.set(p, offset)
    offset += p.length
  }
  return out
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!
  return diff === 0
}

export function isAllZero(b: Uint8Array): boolean {
  let acc = 0
  for (const byte of b) acc |= byte
  return acc === 0
}

export function base64(b: Uint8Array): string {
  let s = ''
  for (const byte of b) s += String.fromCharCode(byte)
  return btoa(s)
}

export function hex(b: Uint8Array): string {
  let s = ''
  for (const byte of b) s += byte.toString(16).padStart(2, '0')
  return s
}
