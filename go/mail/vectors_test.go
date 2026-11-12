// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"flag"
	"os"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
	"github.com/Secria/secria-crypto/go/internal/entropy"
	"github.com/Secria/secria-crypto/go/internal/kat"
)

var update = flag.Bool("update", false, "rewrite the vector file from this implementation")

const vectorPath = "../../test-vectors/mail.json"

type vectorFile struct {
	Spec          string       `json:"spec"`
	Description   string       `json:"description"`
	Bodies        []bodyVector `json:"bodies"`
	InvalidBodies []bodyVector `json:"invalid_bodies"`
	Wraps         []wrapVector `json:"wraps"`
	SelfWraps     []selfVector `json:"self_wraps"`
}

type bodyVector struct {
	Name      string  `json:"name"`
	Key       kat.Hex `json:"key"`
	Plaintext kat.Hex `json:"plaintext"`
	Blob      kat.Hex `json:"blob"`
	// Format is the format the blob decodes as; for invalid bodies, 0.
	Format Format `json:"format"`
	// V2Only says whether the blob must also open in the mode used for
	// messages recorded as format 2.
	V2Only bool `json:"opens_in_v2_only_mode"`
}

type wrapVector struct {
	Name                string  `json:"name"`
	RecipientX25519     kat.Hex `json:"recipient_x25519_private"`
	RecipientMLKEMSeed  kat.Hex `json:"recipient_mlkem_seed"`
	SenderX25519Public  kat.Hex `json:"sender_x25519_public"`
	SenderX25519Private kat.Hex `json:"sender_x25519_private"`
	Key                 kat.Hex `json:"key"`
	EncapsulationSeed   kat.Hex `json:"encapsulation_seed"`
	Salt                kat.Hex `json:"salt"`
	Nonce               kat.Hex `json:"nonce"`
	KEMCiphertext       kat.Hex `json:"kem_ciphertext"`
	WrappedKey          kat.Hex `json:"wrapped_key"`
}

type selfVector struct {
	Name       string  `json:"name"`
	SelfKey    kat.Hex `json:"self_key"`
	Key        kat.Hex `json:"key"`
	Salt       kat.Hex `json:"salt"`
	Nonce      kat.Hex `json:"nonce"`
	WrappedKey kat.Hex `json:"wrapped_key"`
}

func buildVectorFile(t *testing.T) vectorFile {
	f := vectorFile{
		Spec: "spec/mail.md",
		Description: "Mail formats 1 and 2. Bodies must decrypt to the plaintext in the mode for messages whose " +
			"format was not recorded, and, where opens_in_v2_only_mode is true, also in the format-2-only mode. " +
			"Invalid bodies must fail in both modes. Wraps and self wraps must unwrap to the key; wraps must also be " +
			"reproduced exactly from the listed randomness.",
	}
	key := kat.Bytes("body key", KeySize)

	v2 := func(name string, plaintext []byte) bodyVector {
		src := &kat.Source{Values: map[entropy.Kind][][]byte{entropy.Nonce: {kat.Bytes(name+" nonce", aesgcm.NonceSize)}}}
		blob, err := sealBody(src, key, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		return bodyVector{Name: name, Key: key, Plaintext: plaintext, Blob: blob, Format: FormatV2, V2Only: true}
	}
	v1 := func(name string, firstIVByte byte, plaintext []byte) bodyVector {
		iv := kat.Bytes(name+" iv", 16)
		iv[0] = firstIVByte
		return bodyVector{Name: name, Key: key, Plaintext: plaintext, Blob: sealV1(t, key, iv, plaintext), Format: FormatV1}
	}
	f.Bodies = []bodyVector{
		v2("format 2", []byte("Content-Type: text/plain\r\n\r\nHello.")),
		v2("format 2, empty plaintext", []byte{}),
		v1("format 1", 0x00, []byte("Content-Type: text/plain\r\n\r\nHello.")),
		v1("format 1, plaintext a multiple of 16 bytes", 0x00, []byte("exactly sixteen!")),
		v1("format 1 whose IV begins with 0x02", 0x02, []byte("ambiguous with format 2")),
	}
	for i := range f.Bodies {
		if f.Bodies[i].Plaintext == nil {
			f.Bodies[i].Plaintext = kat.Hex{}
		}
	}
	good := f.Bodies[0].Blob
	f.InvalidBodies = []bodyVector{
		{Name: "empty", Key: key, Blob: kat.Hex{}},
		{Name: "format 2 with its tag changed", Key: key, Blob: flipped(good, len(good)-1)},
		{Name: "format 2 truncated to 28 bytes", Key: key, Blob: good[:28]},
		{Name: "format 1 with a partial block", Key: key, Blob: f.Bodies[2].Blob[:len(f.Bodies[2].Blob)-1]},
		{Name: "format 1, IV only", Key: key, Blob: f.Bodies[2].Blob[:16]},
	}

	recipientX := kat.Bytes("recipient x25519", 32)
	recipientSeed := kat.Bytes("recipient mlkem seed", 64)
	senderX := kat.Bytes("sender x25519", 32)
	recipient := publicKeyFromSeed(t, recipientX, recipientSeed)
	sender, err := ecdh.X25519().NewPrivateKey(senderX)
	if err != nil {
		t.Fatal(err)
	}
	wv := wrapVector{
		Name:                "recipient wrap",
		RecipientX25519:     recipientX,
		RecipientMLKEMSeed:  recipientSeed,
		SenderX25519Private: senderX,
		SenderX25519Public:  sender.PublicKey().Bytes(),
		Key:                 kat.Bytes("wrapped key", KeySize),
		EncapsulationSeed:   kat.Bytes("encapsulation", 32),
		Salt:                kat.Bytes("salt", SaltSize),
		Nonce:               kat.Bytes("wrap nonce", aesgcm.NonceSize),
	}
	src := &kat.Source{
		Values: map[entropy.Kind][][]byte{entropy.Salt: {wv.Salt}, entropy.Nonce: {wv.Nonce}},
		Encaps: [][]byte{wv.EncapsulationSeed},
	}
	w, err := sealWrap(src, sender, recipient, wv.Key)
	if err != nil {
		t.Fatal(err)
	}
	wv.KEMCiphertext, wv.WrappedKey = w.KEMCiphertext, w.WrappedKey
	f.Wraps = []wrapVector{wv}

	sv := selfVector{
		Name:    "self wrap",
		SelfKey: kat.Bytes("self key", 32),
		Key:     kat.Bytes("self wrapped key", KeySize),
		Salt:    kat.Bytes("self salt", SaltSize),
		Nonce:   kat.Bytes("self nonce", aesgcm.NonceSize),
	}
	kek, err := hkdf.Key(sha256.New, sv.SelfKey, sv.Salt, wrapInfo, KeySize)
	if err != nil {
		t.Fatal(err)
	}
	sv.WrappedKey, err = aesgcm.Seal(append([]byte(nil), sv.Nonce...), kek, sv.Nonce, sv.Key, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.SelfWraps = []selfVector{sv}
	return f
}

func flipped(b []byte, i int) kat.Hex {
	out := append([]byte(nil), b...)
	out[i] ^= 0x01
	return out
}

func TestVectors(t *testing.T) {
	built := buildVectorFile(t)
	encoded, err := kat.Marshal(built)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile(vectorPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	stored, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stored, encoded) {
		t.Fatalf("%s does not match this implementation; run go test -update if the change is intended", vectorPath)
	}

	for _, v := range built.Bodies {
		got, format, err := OpenBody(v.Key, v.Blob, ModeAuto)
		if err != nil || format != v.Format || !bytes.Equal(got, v.Plaintext) {
			t.Errorf("%s: got %q, format %d, err %v", v.Name, got, format, err)
		}
		_, _, err = OpenBody(v.Key, v.Blob, ModeV2Only)
		if (err == nil) != v.V2Only {
			t.Errorf("%s: format-2-only mode err = %v", v.Name, err)
		}
	}
	for _, v := range built.InvalidBodies {
		for _, mode := range []BodyMode{ModeAuto, ModeV2Only} {
			if _, _, err := OpenBody(v.Key, v.Blob, mode); err == nil {
				t.Errorf("%s opened in mode %d", v.Name, mode)
			}
		}
	}
	for _, v := range built.Wraps {
		kem, err := mlkem.NewDecapsulationKey1024(v.RecipientMLKEMSeed)
		if err != nil {
			t.Fatal(err)
		}
		x, err := ecdh.X25519().NewPrivateKey(v.RecipientX25519)
		if err != nil {
			t.Fatal(err)
		}
		senderPub, err := ecdh.X25519().NewPublicKey(v.SenderX25519Public)
		if err != nil {
			t.Fatal(err)
		}
		sharedKEM, err := kem.Decapsulate(v.KEMCiphertext)
		if err != nil {
			t.Fatal(err)
		}
		sharedX, err := x.ECDH(senderPub)
		if err != nil {
			t.Fatal(err)
		}
		kek, err := wrapKEK(v.Salt, sharedKEM, sharedX)
		if err != nil {
			t.Fatal(err)
		}
		got, err := aesgcm.Open(kek, v.WrappedKey[:aesgcm.NonceSize], v.WrappedKey[aesgcm.NonceSize:], nil)
		if err != nil || !bytes.Equal(got, v.Key) {
			t.Errorf("%s: unwrapped %x, %v", v.Name, got, err)
		}
	}
}
