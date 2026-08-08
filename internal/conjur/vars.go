package conjur

import (
	"fmt"
	"strings"
)

// ParseVarOverrides reads PAM_CONJUR_VARS: a comma-separated list of
// `PAM_SOMETHING=conjur/variable/id` pairs that replace the default
// `<prefix>/<suffix>` convention for individual variables.
//
// It exists because the convention is a guess about someone else's Conjur
// policy. A site whose variables live at `prod/pamv1/keys/api` cannot rename
// them to suit us, and without this the whole integration is unusable there —
// the feature ships and is never turned on, which is the failure mode a
// convention-only design keeps producing.
//
// Everything it can check, it checks, because the entire point is that a typo
// must not look like the feature not working:
//
//   - an unknown PAM_* name is an error (the first version got this right);
//   - so is a malformed variable id — leading/trailing slash, `//`, whitespace,
//     control characters. The first version validated only the left-hand side,
//     so `PAM_API_KEY=prod/keys/apy` parsed clean, 404'd at boot, and left the
//     operator with exactly the silent nothing this promises to prevent. A typo
//     inside a real-looking path still cannot be caught here — Conjur is the
//     only authority on that — which is why a managed variable that later
//     disappears is warned about at refresh time too;
//   - a repeated name is an error rather than last-one-wins, because two
//     mappings for one secret is a mistake with no correct interpretation.
func ParseVarOverrides(raw string) (map[string]string, error) {
	out := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		name, id, ok := strings.Cut(pair, "=")
		name, id = strings.TrimSpace(name), strings.TrimSpace(id)
		if !ok || name == "" || id == "" {
			return nil, fmt.Errorf("PAM_CONJUR_VARS: %q is not NAME=variable/id", pair)
		}
		if !isBootstrapSecret(name) {
			return nil, fmt.Errorf("PAM_CONJUR_VARS: %q is not a sourced bootstrap secret (%s)",
				name, strings.Join(AllSecrets(), ", "))
		}
		if err := validVariableID(id); err != nil {
			return nil, fmt.Errorf("PAM_CONJUR_VARS: %s for %s: %w", id, name, err)
		}
		if prev, dup := out[name]; dup {
			return nil, fmt.Errorf("PAM_CONJUR_VARS: %s is mapped twice (%q and %q); "+
				"two mappings for one secret has no correct interpretation", name, prev, id)
		}
		out[name] = id
	}
	return out, nil
}

// validVariableID rejects the shapes Conjur can never resolve, so they fail at
// startup instead of as a 404 nobody sees.
func validVariableID(id string) error {
	switch {
	case strings.HasPrefix(id, "/") || strings.HasSuffix(id, "/"):
		return fmt.Errorf("must not start or end with %q", "/")
	case strings.Contains(id, "//"):
		return fmt.Errorf("contains an empty path segment")
	case strings.ContainsAny(id, " \t\n\r"):
		return fmt.Errorf("contains whitespace")
	}
	for _, r := range id {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains a control character")
		}
	}
	return nil
}

// isBootstrapSecret reports whether name is one of the sourceable secrets.
func isBootstrapSecret(name string) bool {
	for _, s := range bootstrapSecrets {
		if s.env == name {
			return true
		}
	}
	return false
}

// AllSecrets lists every sourceable bootstrap secret, in declaration order.
func AllSecrets() []string {
	out := make([]string, 0, len(bootstrapSecrets))
	for _, s := range bootstrapSecrets {
		out = append(out, s.env)
	}
	return out
}

// variableID resolves the Conjur variable id for one bootstrap secret: the
// per-variable override if there is one, otherwise `<prefix>/<suffix>`.
func variableID(prefix, suffix, env string, overrides map[string]string) string {
	if id, ok := overrides[env]; ok {
		return id
	}
	return prefix + "/" + suffix
}
