// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

package nodeauth

import (
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
)

type keyPair struct {
	pub, sec []byte
}

func newKeyPair(t *testing.T) keyPair {
	t.Helper()
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return keyPair{pk.Bytes(), sk.Bytes()}
}

func TestRoundTrip(t *testing.T) {
	now := time.Unix(1_794_000_000, 0)
	body := []byte(`{"public_key":"abc"}`)
	kp := newKeyPair(t)
	for _, ctx := range []string{ContextAPIToNode, ContextNodeToAPI} {
		h, err := Sign(kp.sec, ctx, "de-fra-1", "post", "/peers", body, now)
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := Verify(kp.pub, ctx, h, "de-fra-1", "POST", "/peers", body, now.Add(MaxSkew))
		if err != nil || nonce != strings.Split(h, ".")[2] {
			t.Fatalf("%s: nonce %q, %v", ctx, nonce, err)
		}
		other := ContextNodeToAPI
		if ctx == ContextNodeToAPI {
			other = ContextAPIToNode
		}
		for name, err := range map[string]error{
			"context": verifyErr(Verify(kp.pub, other, h, "de-fra-1", "POST", "/peers", body, now)),
			"peer":    verifyErr(Verify(kp.pub, ctx, h, "de-fra-2", "POST", "/peers", body, now)),
			"method":  verifyErr(Verify(kp.pub, ctx, h, "de-fra-1", "DELETE", "/peers", body, now)),
			"path":    verifyErr(Verify(kp.pub, ctx, h, "de-fra-1", "POST", "/peer", body, now)),
			"body":    verifyErr(Verify(kp.pub, ctx, h, "de-fra-1", "POST", "/peers", []byte("{}"), now)),
		} {
			if !errors.Is(err, ErrSignature) {
				t.Errorf("%s, other %s: got %v", ctx, name, err)
			}
		}
		for _, at := range []time.Time{now.Add(MaxSkew + time.Second), now.Add(-MaxSkew - time.Second)} {
			if _, err := Verify(kp.pub, ctx, h, "de-fra-1", "POST", "/peers", body, at); !errors.Is(err, ErrStale) {
				t.Errorf("%s at %v: got %v", ctx, at, err)
			}
		}
	}
}

func verifyErr(_ string, err error) error { return err }

func TestWrongKey(t *testing.T) {
	kp := newKeyPair(t)
	now := time.Unix(1_794_000_000, 0)
	h, err := Sign(kp.sec, ContextAPIToNode, "n1", "GET", "/ping", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(other.Bytes(), ContextAPIToNode, h, "n1", "GET", "/ping", nil, now); !errors.Is(err, ErrSignature) {
		t.Errorf("other key: got %v", err)
	}
	if _, err := Verify(make([]byte, 2592), ContextAPIToNode, h, "n1", "GET", "/ping", nil, now); !errors.Is(err, ErrKey) {
		t.Errorf("2592-byte public key: got %v", err)
	}
	if _, err := Verify(kp.pub[1:], ContextAPIToNode, h, "n1", "GET", "/ping", nil, now); !errors.Is(err, ErrKey) {
		t.Errorf("short public key: got %v", err)
	}
	if _, err := Sign(kp.sec[1:], ContextAPIToNode, "n1", "GET", "/ping", nil, now); !errors.Is(err, ErrKey) {
		t.Errorf("short private key: got %v", err)
	}
}

func TestRefusedFields(t *testing.T) {
	kp := newKeyPair(t)
	now := time.Unix(1_794_000_000, 0)
	for _, f := range [][4]string{
		{"secria-vpn/other/v1", "n1", "GET", "/ping"},
		{ContextAPIToNode, "", "GET", "/ping"},
		{ContextAPIToNode, "n1\n1794000000", "GET", "/ping"},
		{ContextAPIToNode, "n1", "", "/ping"},
		{ContextAPIToNode, "n1", "GET", "/ping\nx"},
		{ContextAPIToNode, "n1\xff", "GET", "/ping"},
		{ContextAPIToNode, "n1", "PO\u017fT", "/ping"},
		{ContextAPIToNode, "n1", "GET ", "/ping"},
	} {
		if _, err := Sign(kp.sec, f[0], f[1], f[2], f[3], nil, now); !errors.Is(err, ErrRequest) {
			t.Errorf("Sign %q: got %v", f, err)
		}
		if _, err := Verify(kp.pub, f[0], "v1.1.n.AA==", f[1], f[2], f[3], nil, now); !errors.Is(err, ErrRequest) {
			t.Errorf("Verify %q: got %v", f, err)
		}
	}
}

func TestMalformedHeaders(t *testing.T) {
	kp := newKeyPair(t)
	now := time.Unix(1_794_000_000, 0)
	h, err := Sign(kp.sec, ContextAPIToNode, "n1", "GET", "/ping", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	p := strings.Split(h, ".")
	for _, bad := range []string{
		"",
		strings.Join(p[:3], "."),
		h + ".x",
		"v2." + strings.Join(p[1:], "."),
		p[0] + ".+1794000000." + strings.Join(p[2:], "."),
		p[0] + ".01794000000." + strings.Join(p[2:], "."),
		p[0] + ".x." + strings.Join(p[2:], "."),
		p[0] + "." + p[1] + ".." + p[3],
		p[0] + ".-1." + strings.Join(p[2:], "."),
		p[0] + "." + p[1] + ".AAAA." + p[3],
		p[0] + "." + p[1] + "." + p[2][:10] + "\r" + p[2][10:] + "." + p[3],
		p[0] + "." + p[1] + "." + p[2] + "A." + p[3],
		strings.Join(p[:3], ".") + "." + p[3][:len(p[3])-1],
		strings.Join(p[:3], ".") + "." + p[3] + "AAAA",
	} {
		if _, err := Verify(kp.pub, ContextAPIToNode, bad, "n1", "GET", "/ping", nil, now); !errors.Is(err, ErrMalformed) {
			t.Errorf("%.40q: got %v", bad, err)
		}
	}
}

func TestSignBefore1970(t *testing.T) {
	kp := newKeyPair(t)
	if _, err := Sign(kp.sec, ContextAPIToNode, "n1", "GET", "/ping", nil, time.Unix(-5, 0)); !errors.Is(err, ErrStale) {
		t.Errorf("got %v", err)
	}
}
