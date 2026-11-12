// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package release

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/cloudflare/circl/sign/slhdsa"
)

const vectorDir = "../../test-vectors/release/"

func readPEMFile(t *testing.T, name, blockType string) []byte {
	t.Helper()
	data, err := os.ReadFile(vectorDir + name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodePEM(data, blockType)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b
}

func TestPublishedManifests(t *testing.T) {
	pub := readPEMFile(t, "release-slhdsa.pub", PEMPublicKey)
	for _, name := range []string{"SHA256SUMS", "SHA256SUMS.linux"} {
		manifest, err := os.ReadFile(vectorDir + name)
		if err != nil {
			t.Fatal(err)
		}
		sig := readPEMFile(t, name+".sig", PEMSignature)
		if err := VerifyManifest(pub, manifest, sig); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		altered := append([]byte(nil), manifest...)
		altered[0] ^= 1
		if err := VerifyManifest(pub, altered, sig); !errors.Is(err, ErrSignature) {
			t.Errorf("%s altered: got %v", name, err)
		}
	}
}

type canaryFile struct {
	Statement  string `json:"statement"`
	Date       string `json:"date"`
	NextUpdate string `json:"next_update"`
	SigAlgo    string `json:"sig_algo"`
	PublicKey  string `json:"public_key"`
	Signature  string `json:"signature"`
}

func TestPublishedCanary(t *testing.T) {
	data, err := os.ReadFile(vectorDir + "canary.json")
	if err != nil {
		t.Fatal(err)
	}
	var c canaryFile
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	if c.SigAlgo != Algorithm {
		t.Fatalf("sig_algo %q", c.SigAlgo)
	}
	pub, err := base64.StdEncoding.DecodeString(c.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.DecodeString(c.Signature)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanary(pub, c.Statement, c.Date, c.NextUpdate, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCanary(pub, c.Statement, c.Date, "2099-01-01", sig); !errors.Is(err, ErrSignature) {
		t.Errorf("changed next update: got %v", err)
	}
	if err := VerifyCanary(pub, c.Statement+"\n"+c.Date, c.Date, c.NextUpdate, sig); !errors.Is(err, ErrCanary) {
		t.Errorf("line feed in statement: got %v", err)
	}
	if err := VerifyCanary(pub, c.Statement, "", c.NextUpdate, sig); !errors.Is(err, ErrCanary) {
		t.Errorf("empty date: got %v", err)
	}
	if err := VerifyCanary(pub, c.Statement+"\xff", c.Date, c.NextUpdate, sig); !errors.Is(err, ErrCanary) {
		t.Errorf("statement not UTF-8: got %v", err)
	}
}

func TestRefusals(t *testing.T) {
	pk, sk, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_256s)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pk.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	message := []byte("abc  file\n")
	sig, err := slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(message), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(pub, message, sig); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(pub[:PublicKeySize-1], message, sig); !errors.Is(err, ErrKey) {
		t.Errorf("short key: got %v", err)
	}
	if err := VerifyManifest(pub, message, sig[:SignatureSize-1]); !errors.Is(err, ErrSignature) {
		t.Errorf("short signature: got %v", err)
	}
	withContext, err := slhdsa.SignDeterministic(&sk, slhdsa.NewMessage(message), []byte("ctx"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest(pub, message, withContext); !errors.Is(err, ErrSignature) {
		t.Errorf("signature with a context: got %v", err)
	}
}

func TestDecodePEM(t *testing.T) {
	block := "-----BEGIN SLH-DSA PUBLIC KEY-----\nAAEC\n-----END SLH-DSA PUBLIC KEY-----\n"
	if b, err := DecodePEM([]byte(block), PEMPublicKey); err != nil || len(b) != 3 {
		t.Fatalf("got %x, %v", b, err)
	}
	for _, bad := range []string{
		"",
		"AAEC",
		block + block,
		"-----BEGIN SLH-DSA SIGNATURE-----\nAAEC\n-----END SLH-DSA SIGNATURE-----\n",
		"-----BEGIN SLH-DSA PUBLIC KEY-----\nKey: value\n\nAAEC\n-----END SLH-DSA PUBLIC KEY-----\n",
		"text before the block\n" + block,
		"-----BEGIN SLH-DSA PUBLIC KEY-----\ntext\n" + block,
		"-----BEGIN SLH-DSA PUBLIC KEY-----\nKEY ONE=\n-----END SLH-DSA PUBLIC KEY-----\n" + block,
		"-----BEGIN SLH-DSA PUBLIC KEY-----\nAAF=\n-----END SLH-DSA PUBLIC KEY-----\n",
	} {
		if _, err := DecodePEM([]byte(bad), PEMPublicKey); !errors.Is(err, ErrPEM) {
			t.Errorf("%q: got %v", bad, err)
		}
	}
}
