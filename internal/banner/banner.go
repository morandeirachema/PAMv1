// Package banner holds the two texts a PAM shows people (Phase 276): a LOGIN
// banner, presented before authentication (the SSH proxy's pre-auth banner,
// the portal's sign-on screen), and a SESSION notice — the recording
// acknowledgement a privacy regime such as the GDPR expects — presented when
// a target session opens: printed into an SSH session (and its recording)
// and required to be acknowledged before a desktop opens in the portal.
// Each text may carry per-language variants (PAM_BANNER_LOGIN_ES, …); a
// language with no variant gets the default.
package banner

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Kinds.
const (
	Login   = "login"
	Session = "session"
)

// Banners is the configured set: kind → language ("" = default) → text.
type Banners struct {
	texts map[string]map[string]string
}

// New builds a set from a flat map of environment-style keys: "login" /
// "session" for the defaults, "login_es" / "session_fr" for variants. Empty
// texts are dropped; a set with no text at all is nil, on which every
// method is a no-op.
func New(kv map[string]string) *Banners {
	b := &Banners{texts: map[string]map[string]string{Login: {}, Session: {}}}
	any := false
	for k, v := range kv {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		k = strings.ToLower(k)
		kind, lang := k, ""
		if i := strings.Index(k, "_"); i > 0 {
			kind, lang = k[:i], k[i+1:]
		}
		if kind != Login && kind != Session {
			continue
		}
		b.texts[kind][lang] = v
		any = true
	}
	if !any {
		return nil
	}
	return b
}

// Get returns the text of kind for lang (an IETF tag; "es-ES" falls back to
// "es", then to the default), or "" when none is configured.
func (b *Banners) Get(kind, lang string) string {
	if b == nil {
		return ""
	}
	m := b.texts[kind]
	lang = strings.ToLower(strings.TrimSpace(lang))
	if t, ok := m[lang]; ok && lang != "" {
		return t
	}
	if i := strings.Index(lang, "-"); i > 0 {
		if t, ok := m[lang[:i]]; ok {
			return t
		}
	}
	return m[""]
}

// Has reports whether any text of kind is configured.
func (b *Banners) Has(kind string) bool {
	return b != nil && len(b.texts[kind]) > 0
}

// Digest is the hex SHA-256 of a text, recorded on the audit row so the
// trail names WHICH notice was shown, not merely that one was.
func Digest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}
