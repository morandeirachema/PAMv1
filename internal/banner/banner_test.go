package banner

import "testing"

func TestBanners(t *testing.T) {
	var none *Banners
	if none.Get(Login, "en") != "" || none.Has(Session) {
		t.Fatal("nil set must be empty")
	}
	if New(map[string]string{"login": "  ", "other": "x"}) != nil {
		t.Fatal("blank texts must yield nil")
	}
	b := New(map[string]string{"login": "Authorized use only", "login_es": "Solo uso autorizado", "session": "This session is recorded", "SESSION_FR": "Cette session est enregistrée"})
	if !b.Has(Login) || !b.Has(Session) {
		t.Fatal("kinds missing")
	}
	cases := map[[2]string]string{
		{Login, ""}:        "Authorized use only",
		{Login, "es"}:      "Solo uso autorizado",
		{Login, "es-MX"}:   "Solo uso autorizado",
		{Login, "de"}:      "Authorized use only",
		{Session, "fr-CA"}: "Cette session est enregistrée",
		{Session, "EN"}:    "This session is recorded",
		{"nonsense", "en"}: "",
	}
	for k, want := range cases {
		if got := b.Get(k[0], k[1]); got != want {
			t.Errorf("Get(%q,%q) = %q want %q", k[0], k[1], got, want)
		}
	}
	// A variant without a default still answers that language only.
	only := New(map[string]string{"session_es": "Grabada"})
	if only.Get(Session, "es") != "Grabada" || only.Get(Session, "") != "" || !only.Has(Session) {
		t.Fatal("variant-only set")
	}
	if len(Digest("x")) != 64 || Digest("x") == Digest("y") {
		t.Fatal("digest")
	}
}
