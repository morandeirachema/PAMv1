// Package jwtutil holds the JWT/JWKS primitives shared by the two independent
// token verifiers in PAMv1 — internal/oidc (OpenID Connect id_tokens) and
// internal/agentid (SPIFFE JWT-SVIDs). Both base64url-decode JWT segments,
// check the "aud" claim, and rebuild an RSA public key from a JWK; keeping one
// copy of each means a security-relevant validator (the audience check
// especially) cannot drift between them, the way the audience check once did —
// one copy guarded an empty claim and the other did not.
//
// This package is a leaf: it imports only the standard library, so any verifier
// can depend on it without a cycle.
package jwtutil

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
)

// JWK is a JSON Web Key as it appears in a JWKS document. The fields cover the
// key types both verifiers accept — RSA (n, e) for OIDC and SPIFFE, plus the EC
// (crv, x, y) and OKP (crv, x) parameters agentid reads for SPIFFE SVIDs. It is
// only ever unmarshaled from a provider's JWKS, so absent fields stay zero.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Crv string `json:"crv,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// DecodeSegment base64url-decodes a JWT segment (header, payload or a JWK field)
// and unmarshals its JSON into v.
func DecodeSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// AudienceContains reports whether the "aud" claim — encoded as either a single
// string or an array of strings — includes want. An empty claim is not a match
// (the guard the two copies once disagreed on): unmarshaling nil into a string
// errors and falls through to false, so this only makes that intent explicit.
func AudienceContains(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// RSAKeyFromJWK reconstructs an RSA public key from a JWK's base64url modulus (n)
// and exponent (e). The caller is responsible for having checked that the key
// type is RSA.
func RSAKeyFromJWK(k JWK) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}
