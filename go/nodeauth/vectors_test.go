// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package nodeauth

import (
	"bytes"
	"encoding/base64"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/Secria/secria-crypto/go/internal/kat"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

var update = flag.Bool("update", false, "rewrite the vector file from this implementation")

const vectorPath = "../../test-vectors/vpn-node-auth.json"

type vectorFile struct {
	Spec        string   `json:"spec"`
	Description string   `json:"description"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	Name      string  `json:"name"`
	Seed      kat.Hex `json:"seed"`
	PublicKey kat.Hex `json:"public_key"`
	Context   string  `json:"context"`
	PeerID    string  `json:"peer_id"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Body      string  `json:"body"`
	Timestamp int64   `json:"timestamp"`
	Nonce     string  `json:"nonce"`
	Header    string  `json:"header"`
}

func buildVectorFile(t *testing.T) vectorFile {
	f := vectorFile{
		Spec: "spec/vpn-node-auth.md",
		Description: "Request signatures between the VPN API and a VPN server. The key pair comes from the 32-byte FIPS 204 " +
			"seed; signing with the deterministic variant of FIPS 204 (rnd = 32 zero bytes) at the listed timestamp and nonce must " +
			"reproduce the header exactly, and Verify must accept it at that timestamp.",
	}
	peerKey := base64.StdEncoding.EncodeToString(kat.Bytes("peer WireGuard key", 32))
	for _, c := range []struct {
		name, ctx, method, path, body string
	}{
		{"ML-DSA-65, API to node", ContextAPIToNode, "POST", "/peers", `{"public_key":"` + peerKey + `"}`},
		{"ML-DSA-65, node to API", ContextNodeToAPI, "GET", "/api/v1/nodes/de-fra-1/config", ""},
	} {
		seed := kat.Bytes(c.name+" seed", 32)
		pk, sk := mldsa65.NewKeyFromSeed((*[32]byte)(seed))
		pub, sec := pk.Bytes(), sk.Bytes()
		v := vector{
			Name:      c.name,
			Seed:      seed,
			PublicKey: pub,
			Context:   c.ctx,
			PeerID:    "de-fra-1",
			Method:    c.method,
			Path:      c.path,
			Body:      c.body,
			Timestamp: 1_794_412_800,
			Nonce:     base64.RawURLEncoding.EncodeToString(kat.Bytes(c.name+" nonce", nonceSize)),
		}
		h, err := sign(sec, v.Context, v.PeerID, v.Method, v.Path, []byte(v.Body), v.Timestamp, v.Nonce, false)
		if err != nil {
			t.Fatal(err)
		}
		v.Header = h
		f.Vectors = append(f.Vectors, v)
	}
	return f
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
	for _, v := range built.Vectors {
		nonce, err := Verify(v.PublicKey, v.Context, v.Header, v.PeerID, v.Method, v.Path, []byte(v.Body), time.Unix(v.Timestamp, 0))
		if err != nil || nonce != v.Nonce {
			t.Errorf("%s: nonce %q, %v", v.Name, nonce, err)
		}
	}
}
