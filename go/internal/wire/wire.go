// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package wire is the length-prefixed encoding of spec/README.md.
package wire

import (
	"encoding/binary"
	"math"
)

type Builder struct {
	b []byte
}

func (w *Builder) Bytes() []byte { return w.b }

func (w *Builder) Raw(b []byte) { w.b = append(w.b, b...) }

// Vec prefixes b with its u32 big-endian length. Callers bound their inputs, so
// the panic is unreachable.
func (w *Builder) Vec(b []byte) {
	if uint64(len(b)) > math.MaxUint32 {
		panic("wire: vec longer than 2^32-1 bytes")
	}
	w.b = binary.BigEndian.AppendUint32(w.b, uint32(len(b)))
	w.Raw(b)
}

func (w *Builder) Str(s string) { w.Vec([]byte(s)) }
