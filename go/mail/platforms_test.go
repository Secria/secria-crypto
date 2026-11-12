// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package mail

// These tests open the mail server's captured output in
// test-vectors/deployed-platforms.json with the Go library, and run the Go
// public-key checks on the VPN apps' key sets there.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
	"github.com/Secria/secria-crypto/go/internal/kat"
)

type captured struct {
	Vaults []struct {
		Name         string  `json:"name"`
		KeyID        kat.Hex `json:"key_id"`
		X25519Public kat.Hex `json:"x25519_public"`
		MLKEMPublic  kat.Hex `json:"mlkem_public"`
	} `json:"vaults"`
	InboundMessages []struct {
		Name           string  `json:"name"`
		ServerX25519   kat.Hex `json:"sender_x25519_public"`
		Key            kat.Hex `json:"key"`
		BodyBlob       kat.Hex `json:"body_blob"`
		Body           kat.Hex `json:"body"`
		AttachmentBlob kat.Hex `json:"attachment_blob"`
		Attachment     kat.Hex `json:"attachment"`
		Recipients     []struct {
			Address       string  `json:"address"`
			X25519Private kat.Hex `json:"recipient_x25519_private"`
			MLKEMSeed     kat.Hex `json:"recipient_mlkem_seed"`
			KeyID         kat.Hex `json:"key_id"`
			KeyUsed       kat.Hex `json:"key_used"`
			KEMCiphertext kat.Hex `json:"kem_ciphertext"`
			Salt          kat.Hex `json:"salt"`
			WrappedKey    kat.Hex `json:"wrapped_key"`
		} `json:"recipients"`
	} `json:"inbound_messages"`
}

const platformsPath = "../../test-vectors/deployed-platforms.json"

func readCaptured(t *testing.T) captured {
	data, err := os.ReadFile(platformsPath)
	if err != nil {
		t.Fatal(err)
	}
	var c captured
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPlatformInboundMail(t *testing.T) {
	c := readCaptured(t)
	if len(c.InboundMessages) == 0 {
		t.Fatal("no inbound messages")
	}
	for _, m := range c.InboundMessages {
		for _, r := range m.Recipients {
			t.Run(r.Address, func(t *testing.T) {
				id := publicKeyFromSeed(t, r.X25519Private, r.MLKEMSeed).KeyID()
				if !bytes.Equal(id[:], r.KeyID) || !bytes.Equal(r.KeyUsed, r.KeyID) {
					t.Fatalf("key_id %x, recorded %x, stored key_used %x", id, []byte(r.KeyID), []byte(r.KeyUsed))
				}
				kem, _ := mlkem.NewDecapsulationKey1024(r.MLKEMSeed)
				x, _ := ecdh.X25519().NewPrivateKey(r.X25519Private)
				server, err := ecdh.X25519().NewPublicKey(m.ServerX25519)
				if err != nil {
					t.Fatal(err)
				}
				sharedKEM, err := kem.Decapsulate(r.KEMCiphertext)
				if err != nil {
					t.Fatal(err)
				}
				sharedX, err := x.ECDH(server)
				if err != nil {
					t.Fatal(err)
				}
				kek, err := wrapKEK(r.Salt, sharedKEM, sharedX)
				if err != nil {
					t.Fatal(err)
				}
				key, err := aesgcm.Open(kek, r.WrappedKey[:aesgcm.NonceSize], r.WrappedKey[aesgcm.NonceSize:], nil)
				if err != nil || !bytes.Equal(key, m.Key) {
					t.Fatalf("recipient wrap: %x, %v", key, err)
				}
				for _, part := range []struct {
					what       string
					blob, want []byte
				}{{"body", m.BodyBlob, m.Body}, {"attachment", m.AttachmentBlob, m.Attachment}} {
					for _, mode := range []BodyMode{ModeV2Only, ModeAuto} {
						got, format, err := OpenBody(key, part.blob, mode)
						if err != nil || format != FormatV2 || !bytes.Equal(got, part.want) {
							t.Fatalf("%s mode %d: format %d, %v, got %s", part.what, mode, format, err, hex.EncodeToString(got))
						}
					}
				}
			})
		}
	}
}

// The Go library holds no private keys, so it checks only the public half:
// FIPS 203 section 7.2 on the ML-KEM key, a valid X25519 key, and the key
// identifier.
func TestPlatformAppPublicKeys(t *testing.T) {
	c := readCaptured(t)
	for _, v := range c.Vaults {
		t.Run(v.Name, func(t *testing.T) {
			pub, err := ParsePublicKey(v.X25519Public, v.MLKEMPublic)
			if err != nil {
				t.Fatal(err)
			}
			id := pub.KeyID()
			if !bytes.Equal(id[:], v.KeyID) {
				t.Fatalf("key_id %x, recorded %x", id, []byte(v.KeyID))
			}
		})
	}
}
