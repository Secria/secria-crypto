// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package aesgcm is AES-256-GCM with a 96-bit nonce and a 128-bit tag.
package aesgcm

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

const (
	KeySize   = 32
	NonceSize = 12
	Overhead  = 16
	// MaxPlaintextSize is from NIST SP 800-38D section 5.2.1.1.
	MaxPlaintextSize uint64 = 1<<36 - 32
)

var ErrOpen = errors.New("aesgcm: message authentication failed")

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("aesgcm: key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Seal(dst, key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errors.New("aesgcm: nonce must be 12 bytes")
	}
	if uint64(len(plaintext)) > MaxPlaintextSize {
		return nil, errors.New("aesgcm: plaintext longer than GCM allows")
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(dst, nonce, plaintext, additionalData), nil
}

func Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize || len(ciphertext) < Overhead {
		return nil, ErrOpen
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrOpen
	}
	return plaintext, nil
}
