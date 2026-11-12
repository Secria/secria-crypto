// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package mail is the mail server's side of spec/mail.md. Clients open wraps
// with the TypeScript package in ts/.
package mail

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/Secria/secria-crypto/go/internal/aesgcm"
	"github.com/Secria/secria-crypto/go/internal/entropy"
)

const (
	KeySize   = 32
	SaltSize  = 32
	KeyIDSize = sha256.Size

	v2Tag     = 0x02
	v2MinSize = 1 + aesgcm.NonceSize + aesgcm.Overhead
	v1MinSize = 2 * aes.BlockSize
	wrapInfo  = "message-key"
)

var (
	// ErrAuthentication does not say whether a body was malformed or unauthentic.
	ErrAuthentication = errors.New("mail: body failed to decrypt")
	ErrKeySize        = errors.New("mail: key must be 32 bytes")
)

type Format int

const (
	// FormatV1 is AES-256-CBC without integrity.
	FormatV1 Format = 1
	FormatV2 Format = 2
)

// BodyMode has no valid zero value, so a caller must choose one.
type BodyMode int

const (
	// ModeAuto falls back to format 1. Never use it for a message recorded as
	// format 2.
	ModeAuto BodyMode = iota + 1
	ModeV2Only
)

func SealBody(key, plaintext []byte) ([]byte, error) {
	return sealBody(entropy.System, key, plaintext)
}

func sealBody(rnd entropy.Source, key, plaintext []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	nonce, err := rnd.Read(entropy.Nonce, aesgcm.NonceSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, 1+aesgcm.NonceSize+len(plaintext)+aesgcm.Overhead)
	out = append(out, v2Tag)
	out = append(out, nonce...)
	return aesgcm.Seal(out, key, nonce, plaintext, nil)
}

// OpenBody's result is authenticated only if its Format is FormatV2.
func OpenBody(key, blob []byte, mode BodyMode) ([]byte, Format, error) {
	if len(key) != KeySize {
		return nil, 0, ErrKeySize
	}
	switch mode {
	case ModeV2Only:
		plaintext, err := openV2(key, blob)
		if err != nil {
			return nil, 0, err
		}
		return plaintext, FormatV2, nil
	case ModeAuto:
		if len(blob) >= v2MinSize && blob[0] == v2Tag {
			if plaintext, err := openV2(key, blob); err == nil {
				return plaintext, FormatV2, nil
			}
		}
		plaintext, err := openV1(key, blob)
		if err != nil {
			return nil, 0, err
		}
		return plaintext, FormatV1, nil
	default:
		return nil, 0, fmt.Errorf("mail: unknown mode %d", mode)
	}
}

func openV2(key, blob []byte) ([]byte, error) {
	if len(blob) < v2MinSize || blob[0] != v2Tag {
		return nil, ErrAuthentication
	}
	nonceEnd := 1 + aesgcm.NonceSize
	plaintext, err := aesgcm.Open(key, blob[1:nonceEnd], blob[nonceEnd:], nil)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func openV1(key, blob []byte) ([]byte, error) {
	if len(blob) < v1MinSize || len(blob)%aes.BlockSize != 0 {
		return nil, ErrAuthentication
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := make([]byte, len(blob)-aes.BlockSize)
	cipher.NewCBCDecrypter(block, blob[:aes.BlockSize]).CryptBlocks(padded, blob[aes.BlockSize:])
	return unpad(padded)
}

// unpad removes PKCS#7 padding. padded is a non-empty multiple of the block
// size.
func unpad(padded []byte) ([]byte, error) {
	n := int(padded[len(padded)-1])
	ok := subtle.ConstantTimeLessOrEq(1, n) & subtle.ConstantTimeLessOrEq(n, aes.BlockSize)
	for i := 1; i <= aes.BlockSize; i++ {
		inPadding := subtle.ConstantTimeLessOrEq(i, n)
		matches := subtle.ConstantTimeByteEq(padded[len(padded)-i], uint8(n))
		ok &= matches | (inPadding ^ 1)
	}
	if ok != 1 {
		return nil, ErrAuthentication
	}
	return padded[:len(padded)-n], nil
}

type PublicKey struct {
	x   *ecdh.PublicKey
	kem *mlkem.EncapsulationKey1024
	id  [KeyIDSize]byte
}

func ParsePublicKey(x25519Key, mlkemKey []byte) (*PublicKey, error) {
	x, err := ecdh.X25519().NewPublicKey(x25519Key)
	if err != nil {
		return nil, fmt.Errorf("mail: X25519 public key: %w", err)
	}
	kem, err := mlkem.NewEncapsulationKey1024(mlkemKey)
	if err != nil {
		return nil, fmt.Errorf("mail: ML-KEM-1024 encapsulation key: %w", err)
	}
	h := sha256.New()
	h.Write(x25519Key)
	h.Write(mlkemKey)
	k := &PublicKey{x: x, kem: kem}
	h.Sum(k.id[:0])
	return k, nil
}

// KeyID is SHA-256(X25519 key ‖ ML-KEM key), or all zero for a nil key.
func (k *PublicKey) KeyID() [KeyIDSize]byte {
	if k == nil {
		return [KeyIDSize]byte{}
	}
	return k.id
}

type Wrap struct {
	KEMCiphertext []byte
	Salt          []byte
	WrappedKey    []byte
}

// SealWrap's sender is the mail server's inbound X25519 key or an account's;
// its public half is stored with the message.
func SealWrap(sender *ecdh.PrivateKey, recipient *PublicKey, key []byte) (*Wrap, error) {
	return sealWrap(entropy.System, sender, recipient, key)
}

func sealWrap(rnd entropy.Source, sender *ecdh.PrivateKey, recipient *PublicKey, key []byte) (*Wrap, error) {
	if len(key) != KeySize {
		return nil, ErrKeySize
	}
	if sender == nil || sender.Curve() != ecdh.X25519() {
		return nil, errors.New("mail: sender must be an X25519 private key")
	}
	if recipient == nil || recipient.x == nil || recipient.kem == nil {
		return nil, errors.New("mail: recipient is not a parsed public key")
	}
	sharedX, err := sender.ECDH(recipient.x)
	if err != nil {
		return nil, fmt.Errorf("mail: recipient X25519 key: %w", err)
	}
	sharedKEM, kemCiphertext, err := rnd.Encapsulate(recipient.kem)
	if err != nil {
		return nil, err
	}
	salt, err := rnd.Read(entropy.Salt, SaltSize)
	if err != nil {
		return nil, err
	}
	kek, err := wrapKEK(salt, sharedKEM, sharedX)
	if err != nil {
		return nil, err
	}
	nonce, err := rnd.Read(entropy.Nonce, aesgcm.NonceSize)
	if err != nil {
		return nil, err
	}
	wrapped, err := aesgcm.Seal(append([]byte(nil), nonce...), kek, nonce, key, nil)
	if err != nil {
		return nil, err
	}
	return &Wrap{KEMCiphertext: kemCiphertext, Salt: salt, WrappedKey: wrapped}, nil
}

func wrapKEK(salt, sharedKEM, sharedX []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(sharedKEM)+len(sharedX))
	ikm = append(ikm, sharedKEM...)
	ikm = append(ikm, sharedX...)
	return hkdf.Key(sha256.New, ikm, salt, wrapInfo, KeySize)
}
