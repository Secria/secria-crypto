// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package release verifies the SLH-DSA signatures on Secria's release
// checksum lists and warrant canary (spec/release-signatures.md).
package release

import (
	"bytes"
	"encoding/pem"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/slhdsa"
)

const (
	Algorithm     = "SLH-DSA-SHA2-256s"
	PublicKeySize = 64
	SignatureSize = 29792
	PEMPublicKey  = "SLH-DSA PUBLIC KEY"
	PEMSignature  = "SLH-DSA SIGNATURE"
)

var (
	ErrKey       = errors.New("release: invalid SLH-DSA-SHA2-256s public key")
	ErrCanary    = errors.New("release: invalid canary field")
	ErrSignature = errors.New("release: signature does not verify")
	ErrPEM       = errors.New("release: not a PEM block of the expected type")
)

// DecodePEM accepts exactly one PEM block of type blockType and nothing else.
func DecodePEM(data []byte, blockType string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != blockType || len(block.Headers) != 0 ||
		!bytes.Equal(bytes.TrimSpace(pem.EncodeToMemory(block)), bytes.TrimSpace(data)) {
		return nil, ErrPEM
	}
	return block.Bytes, nil
}

func verify(publicKey, message, signature []byte) error {
	if len(publicKey) != PublicKeySize {
		return ErrKey
	}
	pk := slhdsa.PublicKey{ID: slhdsa.SHA2_256s}
	if pk.UnmarshalBinary(publicKey) != nil {
		return ErrKey
	}
	if len(signature) != SignatureSize || !slhdsa.Verify(&pk, slhdsa.NewMessage(message), signature, nil) {
		return ErrSignature
	}
	return nil
}

// VerifyManifest takes the checksum list's bytes exactly as downloaded.
func VerifyManifest(publicKey, manifest, signature []byte) error {
	return verify(publicKey, manifest, signature)
}

func CanaryMessage(statement, date, nextUpdate string) ([]byte, error) {
	for _, s := range []string{statement, date, nextUpdate} {
		if s == "" || !utf8.ValidString(s) || strings.ContainsRune(s, '\n') {
			return nil, ErrCanary
		}
	}
	return []byte(statement + "\n" + date + "\n" + nextUpdate), nil
}

// VerifyCanary checks only the signature. The caller refuses any sig_algo but
// Algorithm, and treats the canary as lapsed 24 hours after nextUpdate.
func VerifyCanary(publicKey []byte, statement, date, nextUpdate string, signature []byte) error {
	message, err := CanaryMessage(statement, date, nextUpdate)
	if err != nil {
		return err
	}
	return verify(publicKey, message, signature)
}
