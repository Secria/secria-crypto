// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpsk

import (
	"bytes"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
)

func testBinding() Binding {
	client := make([]byte, WireGuardKeySize)
	server := make([]byte, WireGuardKeySize)
	rand.Read(client)
	rand.Read(server)
	return Binding{ConnectionID: "conn-7f3a", ClientKey: client, ServerKey: server}
}

func testPSK() []byte {
	psk := make([]byte, PSKSize)
	rand.Read(psk)
	return psk
}

func TestV2RoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b, psk := testBinding(), testPSK()
	box, err := SealV2(k.EncapsulationKey(), psk, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != BoxSizeV2 {
		t.Fatalf("box is %d bytes, want %d", len(box), BoxSizeV2)
	}
	got, err := k.Open(box, b)
	if err != nil || !bytes.Equal(got, psk) {
		t.Fatalf("got %x, err %v", got, err)
	}
	if _, err := k.OpenV1(box); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("version 2 box opened as version 1: %v", err)
	}
}

func TestV1RoundTrip(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	psk := testPSK()
	box, err := SealV1(k.EncapsulationKey(), psk)
	if err != nil {
		t.Fatal(err)
	}
	if len(box) != BoxSizeV1 {
		t.Fatalf("box is %d bytes, want %d", len(box), BoxSizeV1)
	}
	got, err := k.OpenV1(box)
	if err != nil || !bytes.Equal(got, psk) {
		t.Fatalf("got %x, err %v", got, err)
	}
	if _, err := k.Open(box, testBinding()); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("version 1 box accepted by the version 2 opener: %v", err)
	}
}

func TestV2IsBoundToTheConnection(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := testBinding()
	box, err := SealV2(k.EncapsulationKey(), testPSK(), b)
	if err != nil {
		t.Fatal(err)
	}
	other := testBinding()
	changes := map[string]Binding{
		"connection id": {ConnectionID: "conn-other", ClientKey: b.ClientKey, ServerKey: b.ServerKey},
		"client key":    {ConnectionID: b.ConnectionID, ClientKey: other.ClientKey, ServerKey: b.ServerKey},
		"server key":    {ConnectionID: b.ConnectionID, ClientKey: b.ClientKey, ServerKey: other.ServerKey},
		"keys swapped":  {ConnectionID: b.ConnectionID, ClientKey: b.ServerKey, ServerKey: b.ClientKey},
	}
	for name, changed := range changes {
		if _, err := k.Open(box, changed); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s changed: err = %v, want ErrAuthentication", name, err)
		}
	}
	if _, err := k.Open(box, Binding{ConnectionID: b.ConnectionID}); !errors.Is(err, ErrBinding) {
		t.Errorf("missing keys: err = %v, want ErrBinding", err)
	}
}

// Flipping the low bit of any byte of a box must make opening fail.
func TestEveryByteIsAuthenticated(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	b := testBinding()
	cases := []struct {
		seal func() ([]byte, error)
		open func([]byte) ([]byte, error)
	}{
		{func() ([]byte, error) { return SealV2(k.EncapsulationKey(), testPSK(), b) }, func(box []byte) ([]byte, error) { return k.Open(box, b) }},
		{func() ([]byte, error) { return SealV1(k.EncapsulationKey(), testPSK()) }, k.OpenV1},
	}
	for _, c := range cases {
		box, err := c.seal()
		if err != nil {
			t.Fatal(err)
		}
		for i := range box {
			box[i] ^= 0x01
			if _, err := c.open(box); err == nil {
				t.Fatalf("%d-byte box: flipping byte %d went undetected", len(box), i)
			}
			box[i] ^= 0x01
		}
	}
}

func TestBoxForAnotherKeyDoesNotOpen(t *testing.T) {
	k1, _ := GenerateKey()
	k2, _ := GenerateKey()
	b := testBinding()
	box, err := SealV2(k1.EncapsulationKey(), testPSK(), b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k2.Open(box, b); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("err = %v, want ErrAuthentication", err)
	}
}

func TestZeroAndNilKeysAreRefused(t *testing.T) {
	for name, k := range map[string]*Key{"zero": new(Key), "nil": nil} {
		if ek := k.EncapsulationKey(); ek != nil {
			t.Errorf("%s Key has encapsulation key %x", name, ek)
		}
		if _, err := k.Open(make([]byte, BoxSizeV2), testBinding()); err == nil {
			t.Errorf("%s Key opened a box", name)
		}
		if _, err := k.OpenV1(make([]byte, BoxSizeV1)); err == nil {
			t.Errorf("%s Key opened a version 1 box", name)
		}
	}
}

func TestSealRejectsInvalidInput(t *testing.T) {
	k, _ := GenerateKey()
	ek := k.EncapsulationKey()
	b := testBinding()
	if _, err := SealV2(ek, testPSK()[:31], b); err == nil {
		t.Error("31-byte PSK sealed")
	}
	if _, err := SealV2(ek[:100], testPSK(), b); err == nil {
		t.Error("truncated encapsulation key accepted")
	}
	bad := append([]byte(nil), ek...)
	bad[0], bad[1] = 0x01, 0x0D // coefficient 3329 fails the FIPS 203 modulus check
	if _, err := SealV2(bad, testPSK(), b); err == nil {
		t.Error("out-of-range encapsulation key accepted")
	}
	if _, err := SealV2(ek, testPSK(), Binding{ConnectionID: "\xff", ClientKey: b.ClientKey, ServerKey: b.ServerKey}); !errors.Is(err, ErrBinding) {
		t.Errorf("invalid UTF-8 connection id: err = %v", err)
	}
	longest := Binding{ConnectionID: strings.Repeat("c", maxConnIDBytes), ClientKey: b.ClientKey, ServerKey: b.ServerKey}
	if _, err := SealV2(ek, testPSK(), longest); err != nil {
		t.Errorf("connection id of %d bytes: %v", maxConnIDBytes, err)
	}
	longest.ConnectionID += "c"
	if _, err := SealV2(ek, testPSK(), longest); !errors.Is(err, ErrBinding) {
		t.Errorf("connection id of %d bytes: err = %v, want ErrBinding", maxConnIDBytes+1, err)
	}
}

// A version 1 box carries the PSK in canonical base64 only (spec/vpn-psk.md
// section 3).
func TestV1RequiresCanonicalBase64(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	sealText := func(text string) []byte {
		ek, err := mlkem.NewEncapsulationKey1024(k.EncapsulationKey())
		if err != nil {
			t.Fatal(err)
		}
		shared, ciphertext := ek.Encapsulate()
		key, err := keyV1(shared)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aesgcm.NonceSize)
		rand.Read(nonce)
		box, err := aesgcm.Seal(append(append([]byte(nil), ciphertext...), nonce...), key, nonce, []byte(text), nil)
		if err != nil {
			t.Fatal(err)
		}
		return box
	}
	canonical := base64.StdEncoding.EncodeToString(testPSK())
	if _, err := k.OpenV1(sealText(canonical)); err != nil {
		t.Fatalf("canonical text: %v", err)
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	last := strings.IndexByte(alphabet, canonical[42])
	for name, text := range map[string]string{
		"an unused bit set":     canonical[:42] + string(alphabet[last|1]) + "=",
		"a newline for the '='": canonical[:43] + "\n",
		"the URL-safe alphabet": strings.NewReplacer("+", "-", "/", "_").Replace(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xFB}, PSKSize))),
	} {
		if _, err := k.OpenV1(sealText(text)); !errors.Is(err, ErrAuthentication) {
			t.Errorf("%s: err = %v, want ErrAuthentication", name, err)
		}
	}
}

func FuzzOpen(f *testing.F) {
	k, _ := GenerateKey()
	b := testBinding()
	v2, _ := SealV2(k.EncapsulationKey(), testPSK(), b)
	v1, _ := SealV1(k.EncapsulationKey(), testPSK())
	f.Add(v2)
	f.Add(v1)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, box []byte) {
		if _, err := k.Open(box, b); err == nil && !bytes.Equal(box, v2) {
			t.Fatal("a modified version 2 box opened")
		}
		if _, err := k.OpenV1(box); err == nil && !bytes.Equal(box, v1) {
			t.Fatal("a modified version 1 box opened")
		}
	})
}
