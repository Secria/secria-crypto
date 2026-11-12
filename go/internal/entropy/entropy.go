// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package entropy is the only source of randomness for sealing, so that
// known-answer tests can replace it.
package entropy

import (
	"crypto/mlkem"
	"crypto/rand"
)

// Kind gives each kind of value its own queue in tests, so that vectors do not
// depend on the order in which an implementation draws them.
type Kind int

const (
	Salt Kind = iota
	Nonce
)

type Source interface {
	Read(kind Kind, n int) ([]byte, error)
	Encapsulate(ek *mlkem.EncapsulationKey1024) (sharedKey, ciphertext []byte, err error)
}

var System Source = system{}

type system struct{}

func (system) Read(_ Kind, n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (system) Encapsulate(ek *mlkem.EncapsulationKey1024) ([]byte, []byte, error) {
	sharedKey, ciphertext := ek.Encapsulate()
	return sharedKey, ciphertext, nil
}
