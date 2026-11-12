// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package kat is a deterministic entropy source for known-answer tests. It
// must never be imported by code that seals real data.
package kat

import (
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/Secria/secria-crypto/go/internal/entropy"
)

type Source struct {
	Values map[entropy.Kind][][]byte
	Encaps [][]byte
}

func (s *Source) Read(kind entropy.Kind, n int) ([]byte, error) {
	q := s.Values[kind]
	if len(q) == 0 {
		return nil, fmt.Errorf("kat: no value queued for kind %d", kind)
	}
	v := q[0]
	s.Values[kind] = q[1:]
	if len(v) != n {
		return nil, fmt.Errorf("kat: kind %d value is %d bytes, want %d", kind, len(v), n)
	}
	return append([]byte(nil), v...), nil
}

func (s *Source) Encapsulate(ek *mlkem.EncapsulationKey1024) ([]byte, []byte, error) {
	if len(s.Encaps) == 0 {
		return nil, nil, fmt.Errorf("kat: no encapsulation randomness queued")
	}
	m := s.Encaps[0]
	s.Encaps = s.Encaps[1:]
	return mlkemtest.Encapsulate1024(ek, m)
}

// Bytes is SHA-256("secria-crypto test vectors" ‖ label ‖ u32(counter)) for
// counter = 0, 1, …, truncated to n.
func Bytes(label string, n int) []byte {
	out := make([]byte, 0, n+sha256.Size)
	for counter := uint32(0); len(out) < n; counter++ {
		h := sha256.New()
		h.Write([]byte("secria-crypto test vectors"))
		h.Write([]byte(label))
		h.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		out = h.Sum(out)
	}
	return out[:n]
}

type Hex []byte

func (h Hex) MarshalJSON() ([]byte, error) {
	if h == nil {
		return []byte("null"), nil
	}
	return json.Marshal(hex.EncodeToString(h))
}

func (h *Hex) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*h = nil
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	*h = v
	return nil
}

func Marshal(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
