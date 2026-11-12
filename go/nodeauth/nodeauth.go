// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

// Package nodeauth signs the requests between Secria's VPN API and VPN
// servers with ML-DSA-65 (spec/vpn-node-auth.md).
package nodeauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

const (
	Header           = "X-PQ-Auth"
	ContextAPIToNode = "secria-vpn/api->node/v1"
	ContextNodeToAPI = "secria-vpn/node->api/v1"
	MaxSkew          = 60 * time.Second

	version   = "v1"
	nonceSize = 16
)

var (
	nonceTextSize = base64.RawURLEncoding.EncodedLen(nonceSize)
	sigTextSize   = base64.StdEncoding.EncodedLen(mldsa65.SignatureSize)
)

var (
	ErrKey       = errors.New("nodeauth: key is not an ML-DSA-65 key")
	ErrRequest   = errors.New("nodeauth: invalid request fields")
	ErrMalformed = errors.New("nodeauth: malformed header")
	ErrStale     = errors.New("nodeauth: timestamp outside the allowed window")
	ErrSignature = errors.New("nodeauth: signature does not verify")
)

func checkRequest(context, peerID, method, path string) error {
	if context != ContextAPIToNode && context != ContextNodeToAPI {
		return ErrRequest
	}
	for _, s := range []string{peerID, path} {
		if s == "" || !utf8.ValidString(s) || strings.ContainsRune(s, '\n') {
			return ErrRequest
		}
	}
	if method == "" {
		return ErrRequest
	}
	for i := 0; i < len(method); i++ {
		if c := method[i] | 0x20; c < 'a' || c > 'z' {
			return ErrRequest
		}
	}
	return nil
}

func payload(peerID string, timestamp int64, nonce, method, path string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return fmt.Appendf(nil, "%s\n%d\n%s\n%s\n%s\n%x", peerID, timestamp, nonce, strings.ToUpper(method), path, sum[:])
}

// Sign's peerID is the VPN server the request is sent to or from.
func Sign(privateKey []byte, context, peerID, method, path string, body []byte, now time.Time) (string, error) {
	if now.Unix() < 0 {
		return "", ErrStale
	}
	n := make([]byte, nonceSize)
	if _, err := rand.Read(n); err != nil {
		return "", err
	}
	return sign(privateKey, context, peerID, method, path, body, now.Unix(), base64.RawURLEncoding.EncodeToString(n), true)
}

func sign(privateKey []byte, context, peerID, method, path string, body []byte, timestamp int64, nonce string, randomized bool) (string, error) {
	if err := checkRequest(context, peerID, method, path); err != nil {
		return "", err
	}
	msg := payload(peerID, timestamp, nonce, method, path, body)
	var sk mldsa65.PrivateKey
	if len(privateKey) != mldsa65.PrivateKeySize || sk.UnmarshalBinary(privateKey) != nil {
		return "", ErrKey
	}
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(&sk, msg, []byte(context), randomized, sig); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s.%d.%s.%s", version, timestamp, nonce, base64.StdEncoding.EncodeToString(sig)), nil
}

// Verify does not detect replays: the caller must keep each nonce it returns
// for longer than 2 × MaxSkew and refuse it if it comes again.
func Verify(publicKey []byte, context, header, peerID, method, path string, body []byte, now time.Time) (string, error) {
	if err := checkRequest(context, peerID, method, path); err != nil {
		return "", err
	}
	parts := strings.Split(header, ".")
	if len(parts) != 4 || parts[0] != version || len(parts[3]) != sigTextSize {
		return "", ErrMalformed
	}
	timestamp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || timestamp < 0 || strconv.FormatInt(timestamp, 10) != parts[1] {
		return "", ErrMalformed
	}
	nonce := parts[2]
	if len(nonce) != nonceTextSize {
		return "", ErrMalformed
	}
	if n, err := base64.RawURLEncoding.Strict().DecodeString(nonce); err != nil || len(n) != nonceSize {
		return "", ErrMalformed
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(parts[3])
	if err != nil {
		return "", ErrMalformed
	}
	if d := now.Sub(time.Unix(timestamp, 0)); d > MaxSkew || d < -MaxSkew {
		return "", ErrStale
	}
	msg := payload(peerID, timestamp, nonce, method, path, body)
	var pk mldsa65.PublicKey
	if len(publicKey) != mldsa65.PublicKeySize || pk.UnmarshalBinary(publicKey) != nil {
		return "", ErrKey
	}
	if !mldsa65.Verify(&pk, msg, []byte(context), sig) {
		return "", ErrSignature
	}
	return nonce, nil
}
