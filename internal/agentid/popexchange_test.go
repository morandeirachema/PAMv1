package agentid

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/morandeirachema/pamv1/internal/jwtutil"
)

// popTestExchanger builds an exchanger over a verifier that accepts the tokens
// the test itself mints, mirroring how main wires the two together.
func popTestExchanger(t *testing.T) (*Exchanger, func(sub string, exp time.Time, cnf string) string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwks := `{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k1","x":"` + b64u(pub) + `"}]}`
	path := t.TempDir() + "/jwks.json"
	if err := writeFile(path, jwks); err != nil {
		t.Fatal(err)
	}
	const aud = "pam-broker"
	verifier, err := NewSVIDVerifier(path, "example.org", aud, 3)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	if err := verifier.TrustIssuer(KeyID(signPub), signPub); err != nil {
		t.Fatal(err)
	}
	x, err := NewExchanger(ExchangerConfig{
		SignKey: signPriv, Audience: aud, TTL: 5 * time.Minute, MaxDepth: 3, Verifier: verifier,
	})
	if err != nil {
		t.Fatal(err)
	}
	mint := func(sub string, exp time.Time, cnf string) string {
		claims := map[string]any{"sub": "spiffe://example.org/" + sub, "aud": aud, "exp": exp.Unix()}
		if cnf != "" {
			claims["cnf"] = map[string]any{"jkt": cnf}
		}
		body, _ := json.Marshal(claims)
		signing := b64u([]byte(`{"alg":"EdDSA","kid":"k1","typ":"JWT"}`)) + "." + b64u(body)
		return signing + "." + b64u(ed25519.Sign(priv, []byte(signing)))
	}
	return x, mint
}

// writeFile is a tiny helper so the fixture above reads in one line.
func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }

// jwkFor renders an ed25519 public key as the JWK its thumbprint is taken over.
func jwkFor(pub ed25519.PublicKey) jwtutil.JWK {
	return jwtutil.JWK{Kty: "OKP", Crv: "Ed25519", X: b64u(pub)}
}

// TestExchangeBindsTheMintedToken proves the whole minting side of Phase 206:
// a `cnf_jkt` becomes an RFC 7800 confirmation on the issued token, the audit
// record names it, and the verifier reads it back as a binding the ingress can
// enforce. Without the last step the claim would be decoration.
func TestExchangeBindsTheMintedToken(t *testing.T) {
	x, mint := popTestExchanger(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jkt, err := JWKThumbprint(jwkFor(pub))
	if err != nil {
		t.Fatal(err)
	}
	delegator, _ := x.verify.Verify(t.Context(), mint("planner", time.Now().Add(time.Hour), ""))

	issued, xerr := x.Exchange(t.Context(), &ExchangeRequest{
		GrantType:  ExchangeGrantType,
		ActorToken: mint("worker", time.Now().Add(time.Hour), ""),
		CnfJKT:     jkt,
	}, delegator)
	if xerr != nil {
		t.Fatalf("exchange: %v", xerr)
	}
	if !strings.Contains(issued.Audit, "cnf_jkt:") || !strings.Contains(issued.Audit, jkt) {
		t.Fatalf("audit does not record the binding: %s", issued.Audit)
	}

	bound, verr := x.verify.Verify(t.Context(), issued.Token)
	if verr != nil {
		t.Fatalf("the minted token did not verify: %v", verr)
	}
	if bound.ConfirmationKey != jkt {
		t.Fatalf("ConfirmationKey = %q, want %q", bound.ConfirmationKey, jkt)
	}

	// An unbound mint stays unbound, and says so by omission on the trail — the
	// absence of the field is the signal that this token is a bearer credential.
	plain, xerr := x.Exchange(t.Context(), &ExchangeRequest{
		GrantType: ExchangeGrantType, ActorToken: mint("worker", time.Now().Add(time.Hour), ""),
	}, delegator)
	if xerr != nil {
		t.Fatal(xerr)
	}
	if strings.Contains(plain.Audit, "cnf_jkt:") {
		t.Fatalf("an unbound mint recorded a binding: %s", plain.Audit)
	}
	unbound, _ := x.verify.Verify(t.Context(), plain.Token)
	if unbound.ConfirmationKey != "" {
		t.Fatalf("ConfirmationKey = %q on an unbound token", unbound.ConfirmationKey)
	}
}

// TestBindingSurvivesTheChain is the rule that makes binding worth anything past
// the first hop: a delegator whose own token is key-bound may not mint an
// unbound one. Without it, the holder of a bound token could exchange it for a
// plain bearer token and walk the constraint off.
func TestBindingSurvivesTheChain(t *testing.T) {
	x, mint := popTestExchanger(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jkt, _ := JWKThumbprint(jwkFor(pub))
	boundDelegator, err := x.verify.Verify(t.Context(), mint("planner", time.Now().Add(time.Hour), jkt))
	if err != nil {
		t.Fatal(err)
	}
	if boundDelegator.ConfirmationKey != jkt {
		t.Fatalf("fixture did not produce a bound delegator: %q", boundDelegator.ConfirmationKey)
	}

	_, xerr := x.Exchange(t.Context(), &ExchangeRequest{
		GrantType: ExchangeGrantType, ActorToken: mint("worker", time.Now().Add(time.Hour), ""),
	}, boundDelegator)
	if xerr == nil {
		t.Fatal("a key-bound delegator minted an unbound token")
	}
	if !strings.Contains(xerr.Error(), "cnf_jkt is required") {
		t.Fatalf("refusal = %v, want it to name cnf_jkt", xerr)
	}

	// Naming a key — its own or the sub-agent's — is all it takes to proceed.
	if _, xerr := x.Exchange(t.Context(), &ExchangeRequest{
		GrantType: ExchangeGrantType, ActorToken: mint("worker", time.Now().Add(time.Hour), ""),
		CnfJKT: jkt,
	}, boundDelegator); xerr != nil {
		t.Fatalf("a bound delegator could not mint a bound token: %v", xerr)
	}
}

// TestExchangeRefusesAMalformedBinding: a thumbprint no key can ever produce
// would mint a token nothing could present, and the client would not find out
// until every call it made failed. Refuse at the mint, where the mistake is.
func TestExchangeRefusesAMalformedBinding(t *testing.T) {
	x, mint := popTestExchanger(t)
	delegator, _ := x.verify.Verify(t.Context(), mint("planner", time.Now().Add(time.Hour), ""))
	for _, bad := range []string{"too-short", strings.Repeat("A", ThumbprintLen+1), strings.Repeat("+", ThumbprintLen)} {
		_, xerr := x.Exchange(t.Context(), &ExchangeRequest{
			GrantType: ExchangeGrantType, ActorToken: mint("worker", time.Now().Add(time.Hour), ""),
			CnfJKT: bad,
		}, delegator)
		if xerr == nil {
			t.Fatalf("cnf_jkt %q was accepted", bad)
		}
	}
}

// TestVerifierRefusesAnUnenforceableConfirmation is the fail-closed half of the
// claim. RFC 7800 also defines `jwk` and `kid` confirmations; pamv1 enforces only
// `jkt`. Reading such a token as "unbound" would DOWNGRADE a token its issuer had
// deliberately constrained, so it is refused outright instead.
func TestVerifierRefusesAnUnenforceableConfirmation(t *testing.T) {
	x, mint := popTestExchanger(t)
	for _, bad := range []string{"short", strings.Repeat("A", ThumbprintLen+1)} {
		if _, err := x.verify.Verify(t.Context(), mint("planner", time.Now().Add(time.Hour), bad)); err == nil {
			t.Fatalf("a token whose cnf.jkt was %q verified", bad)
		}
	}
}

// TestParseExchangeFormReadsCnfJKT pins the wire name, and that a repeated
// parameter is refused like every other one — an ambiguous body on a
// security-relevant request is a bug or an attack, and picking a winner hides
// both.
func TestParseExchangeFormReadsCnfJKT(t *testing.T) {
	req, err := ParseExchangeForm(map[string][]string{"cnf_jkt": {" abc "}})
	if err != nil {
		t.Fatal(err)
	}
	if req.CnfJKT != "abc" {
		t.Fatalf("CnfJKT = %q, want abc", req.CnfJKT)
	}
	if _, err := ParseExchangeForm(map[string][]string{"cnf_jkt": {"a", "b"}}); err == nil {
		t.Fatal("a repeated cnf_jkt was accepted")
	}
}
