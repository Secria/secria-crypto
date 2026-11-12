// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
)

// publicKeyFromSeed returns the public half of a key set given as the vectors
// give it: an X25519 private key and a 64-byte ML-KEM-1024 seed.
func publicKeyFromSeed(t testing.TB, x25519Private, mlkemSeed []byte) *PublicKey {
	t.Helper()
	x, err := ecdh.X25519().NewPrivateKey(x25519Private)
	if err != nil {
		t.Fatal(err)
	}
	kem, err := mlkem.NewDecapsulationKey1024(mlkemSeed)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(x.PublicKey().Bytes(), kem.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func randomKey(t testing.TB) []byte {
	t.Helper()
	k := make([]byte, KeySize)
	rand.Read(k)
	return k
}

// sealV1 writes format 1 the way clients did before format 2.
func sealV1(t testing.TB, key, iv, plaintext []byte) []byte {
	t.Helper()
	n := aes.BlockSize - len(plaintext)%aes.BlockSize
	padded := append(append([]byte(nil), plaintext...), bytes.Repeat([]byte{byte(n)}, n)...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), iv...)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return append(out, ct...)
}

func TestFormat2RoundTrip(t *testing.T) {
	key := randomKey(t)
	for _, plaintext := range [][]byte{{}, []byte("x"), bytes.Repeat([]byte("body "), 1000)} {
		blob, err := SealBody(key, plaintext)
		if err != nil {
			t.Fatal(err)
		}
		for _, mode := range []BodyMode{ModeAuto, ModeV2Only} {
			got, format, err := OpenBody(key, blob, mode)
			if err != nil || format != FormatV2 || !bytes.Equal(got, plaintext) {
				t.Fatalf("mode %d, %d-byte plaintext: got %q, format %d, err %v", mode, len(plaintext), got, format, err)
			}
		}
	}
}

func TestFormat1(t *testing.T) {
	key := randomKey(t)
	for _, firstIVByte := range []byte{0x00, 0x02} {
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		iv[0] = firstIVByte
		for _, plaintext := range [][]byte{{}, []byte("exactly sixteen!"), []byte("format 1 body")} {
			blob := sealV1(t, key, iv, plaintext)
			got, format, err := OpenBody(key, blob, ModeAuto)
			if err != nil || format != FormatV1 || !bytes.Equal(got, plaintext) {
				t.Fatalf("IV byte 0x%02x, %q: got %q, format %d, err %v", firstIVByte, plaintext, got, format, err)
			}
			if _, _, err := OpenBody(key, blob, ModeV2Only); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("format 1 accepted in ModeV2Only: %v", err)
			}
		}
	}
}

func TestMalformedBodiesFailWithoutPanic(t *testing.T) {
	key := randomKey(t)
	for n := 0; n <= 80; n++ {
		blob := make([]byte, n)
		rand.Read(blob)
		if n > 0 && n%2 == 0 {
			blob[0] = v2Tag
		}
		// Random bytes of a format 1 length decrypt to valid padding about
		// once in 256 tries; format 1 cannot tell that apart from real data.
		couldBeFormat1 := n >= v1MinSize && n%aes.BlockSize == 0
		for _, mode := range []BodyMode{ModeAuto, ModeV2Only} {
			_, _, err := OpenBody(key, blob, mode)
			if err == nil && mode == ModeAuto && couldBeFormat1 {
				continue
			}
			if !errors.Is(err, ErrAuthentication) {
				t.Fatalf("%d random bytes, mode %d: err = %v", n, mode, err)
			}
		}
	}
	if _, _, err := OpenBody(key[:16], nil, ModeAuto); !errors.Is(err, ErrKeySize) {
		t.Fatalf("16-byte key: err = %v", err)
	}
}

func TestPaddingIsFullyChecked(t *testing.T) {
	key := randomKey(t)
	iv := make([]byte, aes.BlockSize)
	block, _ := aes.NewCipher(key)
	encrypt := func(last []byte) []byte {
		ct := make([]byte, aes.BlockSize)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, last)
		return append(append([]byte(nil), iv...), ct...)
	}
	bad := map[string][]byte{
		"zero":            append(bytes.Repeat([]byte{'a'}, 15), 0x00),
		"seventeen":       append(bytes.Repeat([]byte{'a'}, 15), 0x11),
		"inconsistent":    append(bytes.Repeat([]byte{'a'}, 13), 0x03, 0x02, 0x03),
		"first byte off":  append([]byte{0x0F}, bytes.Repeat([]byte{0x10}, 15)...),
		"one short of 16": append([]byte{'a'}, bytes.Repeat([]byte{0x10}, 15)...),
	}
	for name, last := range bad {
		if _, _, err := OpenBody(key, encrypt(last), ModeAuto); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s padding accepted: %v", name, err)
		}
	}
	got, _, err := OpenBody(key, encrypt(bytes.Repeat([]byte{0x10}, 16)), ModeAuto)
	if err != nil || len(got) != 0 {
		t.Errorf("full padding block: got %q, %v", got, err)
	}
}

func TestSealWrap(t *testing.T) {
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKEM, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(recipientX.PublicKey().Bytes(), recipientKEM.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	key := randomKey(t)
	w, err := SealWrap(sender, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.KEMCiphertext) != mlkem.CiphertextSize1024 || len(w.Salt) != SaltSize || len(w.WrappedKey) != aesgcm.NonceSize+KeySize+aesgcm.Overhead {
		t.Fatalf("field sizes %d, %d, %d", len(w.KEMCiphertext), len(w.Salt), len(w.WrappedKey))
	}

	// Open it the way a recipient does (spec/mail.md section 4).
	sharedKEM, err := recipientKEM.Decapsulate(w.KEMCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	sharedX, err := recipientX.ECDH(sender.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	kek, err := hkdf.Key(sha256.New, append(sharedKEM, sharedX...), w.Salt, "message-key", 32)
	if err != nil {
		t.Fatal(err)
	}
	got, err := aesgcm.Open(kek, w.WrappedKey[:aesgcm.NonceSize], w.WrappedKey[aesgcm.NonceSize:], nil)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("unwrapped %x, %v; want %x", got, err, key)
	}

	if _, err := SealWrap(sender, pub, key[:31]); !errors.Is(err, ErrKeySize) {
		t.Errorf("31-byte key: err = %v", err)
	}
}

func FuzzOpenBody(f *testing.F) {
	key := make([]byte, KeySize)
	v2, _ := SealBody(key, []byte("seed"))
	f.Add(v2)
	f.Add(sealV1(f, key, make([]byte, aes.BlockSize), []byte("seed")))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, blob []byte) {
		for _, mode := range []BodyMode{ModeAuto, ModeV2Only} {
			if _, _, err := OpenBody(key, blob, mode); err != nil && !errors.Is(err, ErrAuthentication) {
				t.Fatalf("unexpected error: %v", err)
			}
		}
	})
}

// A low-order recipient key gives an all-zero X25519 output, which sealing
// must refuse (spec/README.md, Primitives).
func TestSealWrapRefusesLowOrderKey(t *testing.T) {
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recipientKEM, err := mlkem.GenerateKey1024()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKey(make([]byte, 32), recipientKEM.EncapsulationKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealWrap(sender, pub, randomKey(t)); err == nil {
		t.Fatal("a wrap was sealed to a low-order X25519 key")
	}
}

// A mode must be chosen: the zero value, or any other unknown one, must not
// fall back to format 1.
func TestUnknownModeIsRefused(t *testing.T) {
	key := randomKey(t)
	iv := make([]byte, aes.BlockSize)
	blobs := [][]byte{sealV1(t, key, iv, []byte("format 1 body"))}
	v2, err := SealBody(key, []byte("format 2 body"))
	if err != nil {
		t.Fatal(err)
	}
	blobs = append(blobs, v2)
	for _, mode := range []BodyMode{0, ModeV2Only + 1, -1} {
		for _, blob := range blobs {
			if got, _, err := OpenBody(key, blob, mode); err == nil {
				t.Errorf("mode %d opened %q", mode, got)
			}
		}
	}
}

func TestZeroPublicKeyIsRefused(t *testing.T) {
	sender, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, pub := range map[string]*PublicKey{"zero": new(PublicKey), "nil": nil} {
		if id := pub.KeyID(); id != [KeyIDSize]byte{} {
			t.Errorf("%s PublicKey has key_id %x", name, id)
		}
		if _, err := SealWrap(sender, pub, randomKey(t)); err == nil {
			t.Errorf("a wrap was sealed to a %s PublicKey", name)
		}
	}
}
