// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package mail

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
	"github.com/Secria/secria-crypto/go/internal/kat"
)

// TestDeployedMessages opens mail written by the code Secria's apps ship
// (test-vectors/deployed.json).
func TestDeployedMessages(t *testing.T) {
	var file struct {
		Messages []struct {
			Name               string  `json:"name"`
			RecipientX25519    kat.Hex `json:"recipient_x25519_private"`
			RecipientMLKEMSeed kat.Hex `json:"recipient_mlkem_seed"`
			SenderX25519Public kat.Hex `json:"sender_x25519_public"`
			KEMCiphertext      kat.Hex `json:"kem_ciphertext"`
			Salt               kat.Hex `json:"salt"`
			WrappedKey         kat.Hex `json:"wrapped_key"`
			Key                kat.Hex `json:"key"`
			BodyBlob           kat.Hex `json:"body_blob"`
			Body               kat.Hex `json:"body"`
			SenderSelfKey      kat.Hex `json:"sender_self_key"`
			SelfSalt           kat.Hex `json:"self_salt"`
			SelfWrappedKey     kat.Hex `json:"self_wrapped_key"`
		} `json:"messages"`
	}
	data, err := os.ReadFile("../../test-vectors/deployed.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Messages) == 0 {
		t.Fatal("no deployed messages")
	}
	for _, m := range file.Messages {
		kem, err := mlkem.NewDecapsulationKey1024(m.RecipientMLKEMSeed)
		if err != nil {
			t.Fatal(err)
		}
		x, err := ecdh.X25519().NewPrivateKey(m.RecipientX25519)
		if err != nil {
			t.Fatal(err)
		}
		senderPub, err := ecdh.X25519().NewPublicKey(m.SenderX25519Public)
		if err != nil {
			t.Fatal(err)
		}
		sharedKEM, err := kem.Decapsulate(m.KEMCiphertext)
		if err != nil {
			t.Fatal(err)
		}
		sharedX, err := x.ECDH(senderPub)
		if err != nil {
			t.Fatal(err)
		}
		kek, err := wrapKEK(m.Salt, sharedKEM, sharedX)
		if err != nil {
			t.Fatal(err)
		}
		key, err := aesgcm.Open(kek, m.WrappedKey[:aesgcm.NonceSize], m.WrappedKey[aesgcm.NonceSize:], nil)
		if err != nil || !bytes.Equal(key, m.Key) {
			t.Fatalf("%s: recipient wrap: %x, %v", m.Name, key, err)
		}
		body, format, err := OpenBody(key, m.BodyBlob, ModeV2Only)
		if err != nil || format != FormatV2 || !bytes.Equal(body, m.Body) {
			t.Fatalf("%s: body: %q, %v", m.Name, body, err)
		}
		selfKEK, err := hkdf.Key(sha256.New, m.SenderSelfKey, m.SelfSalt, wrapInfo, KeySize)
		if err != nil {
			t.Fatal(err)
		}
		selfKey, err := aesgcm.Open(selfKEK, m.SelfWrappedKey[:aesgcm.NonceSize], m.SelfWrappedKey[aesgcm.NonceSize:], nil)
		if err != nil || !bytes.Equal(selfKey, m.Key) {
			t.Fatalf("%s: self wrap: %x, %v", m.Name, selfKey, err)
		}
	}
}
