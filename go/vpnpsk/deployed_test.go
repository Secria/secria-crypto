// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package vpnpsk

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/Secria/secria-crypto/go/internal/kat"
)

// TestDeployedBoxes opens boxes sealed by the code Secria's VPN API runs
// (test-vectors/deployed.json).
func TestDeployedBoxes(t *testing.T) {
	var file struct {
		Boxes []struct {
			Name            string  `json:"name"`
			ClientMLKEMSeed kat.Hex `json:"client_mlkem_seed"`
			PSK             kat.Hex `json:"psk"`
			Box             kat.Hex `json:"box"`
		} `json:"vpn_boxes"`
	}
	data, err := os.ReadFile("../../test-vectors/deployed.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Boxes) == 0 {
		t.Fatal("no deployed boxes")
	}
	for _, b := range file.Boxes {
		k, err := NewKey(b.ClientMLKEMSeed)
		if err != nil {
			t.Fatal(err)
		}
		psk, err := k.OpenV1(b.Box)
		if err != nil || !bytes.Equal(psk, b.PSK) {
			t.Errorf("%s: got %x, %v", b.Name, psk, err)
		}
	}
}
