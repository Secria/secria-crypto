// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpsk

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/entropy"
	"github.com/Secria/secria-crypto/go/internal/kat"
)

var update = flag.Bool("update", false, "rewrite the vector file from this implementation")

const vectorPath = "../../test-vectors/vpn-psk.json"

type vectorFile struct {
	Spec        string   `json:"spec"`
	Description string   `json:"description"`
	Vectors     []vector `json:"vectors"`
}

type vector struct {
	Name              string  `json:"name"`
	Version           int     `json:"version"`
	ClientMLKEMSeed   kat.Hex `json:"client_mlkem_seed"`
	EncapsulationKey  kat.Hex `json:"encapsulation_key"`
	ConnectionID      string  `json:"connection_id"`
	ClientKey         kat.Hex `json:"client_wireguard_public"`
	ServerKey         kat.Hex `json:"server_wireguard_public"`
	PSK               kat.Hex `json:"psk"`
	EncapsulationSeed kat.Hex `json:"encapsulation_seed"`
	Nonce             kat.Hex `json:"nonce"`
	Box               kat.Hex `json:"box"`
}

func buildVectorFile(t *testing.T) vectorFile {
	f := vectorFile{
		Spec: "spec/vpn-psk.md",
		Description: "VPN pre-shared-key boxes. Sealing with the listed encapsulation seed (FIPS 203 randomness m) and " +
			"nonce must reproduce the box exactly, and the client key derived from the 64-byte seed must open it to the " +
			"PSK. Version 1 boxes carry no binding.",
	}
	for _, version := range []int{2, 1} {
		name := map[int]string{1: "version 1", 2: "version 2"}[version]
		seed := kat.Bytes(name+" client seed", 64)
		k, err := NewKey(seed)
		if err != nil {
			t.Fatal(err)
		}
		v := vector{
			Name:              name,
			Version:           version,
			ClientMLKEMSeed:   seed,
			EncapsulationKey:  k.EncapsulationKey(),
			PSK:               kat.Bytes(name+" psk", PSKSize),
			EncapsulationSeed: kat.Bytes(name+" encapsulation", 32),
			Nonce:             kat.Bytes(name+" nonce", 12),
		}
		src := &kat.Source{
			Values: map[entropy.Kind][][]byte{entropy.Nonce: {v.Nonce}},
			Encaps: [][]byte{v.EncapsulationSeed},
		}
		if version == 2 {
			v.ConnectionID = "c0nn-9f2e-4b1d"
			v.ClientKey = kat.Bytes(name+" client wireguard", WireGuardKeySize)
			v.ServerKey = kat.Bytes(name+" server wireguard", WireGuardKeySize)
			v.Box, err = sealV2(src, v.EncapsulationKey, v.PSK, Binding{ConnectionID: v.ConnectionID, ClientKey: v.ClientKey, ServerKey: v.ServerKey})
		} else {
			v.Box, err = sealV1(src, v.EncapsulationKey, v.PSK)
		}
		if err != nil {
			t.Fatal(err)
		}
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
		k, err := NewKey(v.ClientMLKEMSeed)
		if err != nil {
			t.Fatal(err)
		}
		var psk []byte
		if v.Version == 2 {
			psk, err = k.Open(v.Box, Binding{ConnectionID: v.ConnectionID, ClientKey: v.ClientKey, ServerKey: v.ServerKey})
		} else {
			psk, err = k.OpenV1(v.Box)
		}
		if err != nil || !bytes.Equal(psk, v.PSK) {
			t.Errorf("%s: got %x, err %v", v.Name, psk, err)
		}
	}
}
