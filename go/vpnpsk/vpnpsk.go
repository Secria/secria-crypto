// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package vpnpsk seals the WireGuard pre-shared key that Secria's VPN API
// sends to a client (spec/vpn-psk.md).
package vpnpsk

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
	"github.com/Secria/secria-crypto/go/internal/entropy"
	"github.com/Secria/secria-crypto/go/internal/wire"
)

const (
	PSKSize          = 32
	WireGuardKeySize = 32
	BoxSizeV2        = 1 + mlkem.CiphertextSize1024 + aesgcm.NonceSize + PSKSize + aesgcm.Overhead
	BoxSizeV1        = mlkem.CiphertextSize1024 + aesgcm.NonceSize + pskTextSize + aesgcm.Overhead

	versionV2      = 0x02
	labelV2Key     = "secria/vpnpsk/v2/key"
	labelV2Box     = "secria/vpnpsk/v2/box"
	infoV1         = "SecriaVPN-PSK-ML-KEM-1024-v1"
	pskTextSize    = 44
	maxConnIDBytes = 4096
)

var (
	// ErrAuthentication does not say why a box failed to open.
	ErrAuthentication = errors.New("vpnpsk: box failed to open")
	ErrBinding        = errors.New("vpnpsk: invalid binding")
)

// Binding ties a version 2 box to one connection.
type Binding struct {
	ConnectionID string
	// ClientKey comes from the client's own key pair, never from the response.
	ClientKey []byte
	ServerKey []byte
}

func (b *Binding) associatedData() ([]byte, error) {
	if len(b.ClientKey) != WireGuardKeySize || len(b.ServerKey) != WireGuardKeySize ||
		len(b.ConnectionID) > maxConnIDBytes || !utf8.ValidString(b.ConnectionID) {
		return nil, ErrBinding
	}
	var w wire.Builder
	w.Vec([]byte(labelV2Box))
	w.Str(b.ConnectionID)
	w.Raw(b.ClientKey)
	w.Raw(b.ServerKey)
	return w.Bytes(), nil
}

func keyV2(sharedKey, ek, ciphertext []byte) ([]byte, error) {
	ekHash := sha256.Sum256(ek)
	ctHash := sha256.Sum256(ciphertext)
	var info wire.Builder
	info.Vec([]byte(labelV2Key))
	info.Raw(ekHash[:])
	info.Raw(ctHash[:])
	return hkdf.Key(sha256.New, sharedKey, nil, string(info.Bytes()), aesgcm.KeySize)
}

func keyV1(sharedKey []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, sharedKey, nil, infoV1, aesgcm.KeySize)
}

func SealV2(encapsulationKey, psk []byte, b Binding) ([]byte, error) {
	return sealV2(entropy.System, encapsulationKey, psk, b)
}

func sealV2(rnd entropy.Source, encapsulationKey, psk []byte, b Binding) ([]byte, error) {
	if len(psk) != PSKSize {
		return nil, fmt.Errorf("vpnpsk: psk is %d bytes, want %d", len(psk), PSKSize)
	}
	ad, err := b.associatedData()
	if err != nil {
		return nil, err
	}
	ek, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("vpnpsk: encapsulation key: %w", err)
	}
	sharedKey, ciphertext, err := rnd.Encapsulate(ek)
	if err != nil {
		return nil, err
	}
	key, err := keyV2(sharedKey, encapsulationKey, ciphertext)
	if err != nil {
		return nil, err
	}
	nonce, err := rnd.Read(entropy.Nonce, aesgcm.NonceSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, BoxSizeV2)
	out = append(out, versionV2)
	out = append(out, ciphertext...)
	out = append(out, nonce...)
	return aesgcm.Seal(out, key, nonce, psk, ad)
}

func SealV1(encapsulationKey, psk []byte) ([]byte, error) {
	return sealV1(entropy.System, encapsulationKey, psk)
}

func sealV1(rnd entropy.Source, encapsulationKey, psk []byte) ([]byte, error) {
	if len(psk) != PSKSize {
		return nil, fmt.Errorf("vpnpsk: psk is %d bytes, want %d", len(psk), PSKSize)
	}
	ek, err := mlkem.NewEncapsulationKey1024(encapsulationKey)
	if err != nil {
		return nil, fmt.Errorf("vpnpsk: encapsulation key: %w", err)
	}
	sharedKey, ciphertext, err := rnd.Encapsulate(ek)
	if err != nil {
		return nil, err
	}
	key, err := keyV1(sharedKey)
	if err != nil {
		return nil, err
	}
	nonce, err := rnd.Read(entropy.Nonce, aesgcm.NonceSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, BoxSizeV1)
	out = append(out, ciphertext...)
	out = append(out, nonce...)
	return aesgcm.Seal(out, key, nonce, []byte(base64.StdEncoding.EncodeToString(psk)), nil)
}

type Key struct {
	dk *mlkem.DecapsulationKey1024
}

// GenerateKey returns a key pair for one connection only.
func GenerateKey() (*Key, error) {
	dk, err := mlkem.GenerateKey1024()
	if err != nil {
		return nil, err
	}
	return &Key{dk: dk}, nil
}

// NewKey derives a key pair from a 64-byte seed. Clients use GenerateKey.
func NewKey(seed []byte) (*Key, error) {
	dk, err := mlkem.NewDecapsulationKey1024(seed)
	if err != nil {
		return nil, err
	}
	return &Key{dk: dk}, nil
}

func (k *Key) EncapsulationKey() []byte {
	if k == nil || k.dk == nil {
		return nil
	}
	return k.dk.EncapsulationKey().Bytes()
}

func (k *Key) Open(box []byte, b Binding) ([]byte, error) {
	if k == nil || k.dk == nil {
		return nil, errors.New("vpnpsk: key is not initialised")
	}
	if len(box) != BoxSizeV2 || box[0] != versionV2 {
		return nil, ErrAuthentication
	}
	return k.openV2(box, b)
}

func (k *Key) OpenV1(box []byte) ([]byte, error) {
	if k == nil || k.dk == nil {
		return nil, errors.New("vpnpsk: key is not initialised")
	}
	if len(box) != BoxSizeV1 {
		return nil, ErrAuthentication
	}
	return k.openV1(box)
}

func (k *Key) openV2(box []byte, b Binding) ([]byte, error) {
	ad, err := b.associatedData()
	if err != nil {
		return nil, err
	}
	ctEnd := 1 + mlkem.CiphertextSize1024
	nonceEnd := ctEnd + aesgcm.NonceSize
	ciphertext := box[1:ctEnd]
	sharedKey, err := k.dk.Decapsulate(ciphertext)
	if err != nil {
		return nil, ErrAuthentication
	}
	key, err := keyV2(sharedKey, k.EncapsulationKey(), ciphertext)
	if err != nil {
		return nil, err
	}
	psk, err := aesgcm.Open(key, box[ctEnd:nonceEnd], box[nonceEnd:], ad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return psk, nil
}

func (k *Key) openV1(box []byte) ([]byte, error) {
	ctEnd := mlkem.CiphertextSize1024
	nonceEnd := ctEnd + aesgcm.NonceSize
	sharedKey, err := k.dk.Decapsulate(box[:ctEnd])
	if err != nil {
		return nil, ErrAuthentication
	}
	key, err := keyV1(sharedKey)
	if err != nil {
		return nil, err
	}
	text, err := aesgcm.Open(key, box[ctEnd:nonceEnd], box[nonceEnd:], nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	psk, err := base64.StdEncoding.Strict().DecodeString(string(text))
	if err != nil || len(psk) != PSKSize {
		return nil, ErrAuthentication
	}
	return psk, nil
}
