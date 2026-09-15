package store_test

import (
	"reflect"
	"testing"

	"github.com/morandeirachema/pamv1/internal/store"
)

// TestSafePermissionVocabulary pins how a permission set is read and written
// (Phase 246): canonical order, duplicates dropped, an unknown name refused on
// the way in and ignored on the way out, and an empty set kept distinct from
// "not named".
func TestSafePermissionVocabulary(t *testing.T) {
	got, err := store.NormalizeSafePermissions([]string{"approve", "use", "use"})
	if err != nil || !reflect.DeepEqual(got, []string{"use", "approve"}) {
		t.Fatalf("Normalize = %v, %v", got, err)
	}
	if _, err := store.NormalizeSafePermissions([]string{"root"}); err == nil {
		t.Fatal("an unknown permission must be refused")
	}
	if got, _ := store.NormalizeSafePermissions(nil); got == nil || len(got) != 0 {
		t.Fatalf("Normalize(nil) = %#v, want an empty non-nil set", got)
	}
	if got := store.ParseSafePermissions("retrieve,bogus,use,use"); !reflect.DeepEqual(got, []string{"use", "retrieve"}) {
		t.Fatalf("Parse = %v", got)
	}
	if got := store.ParseSafePermissions(""); got == nil || len(got) != 0 {
		t.Fatalf("Parse(\"\") = %#v, want an empty non-nil set", got)
	}
	if got := store.JoinSafePermissions(store.DefaultSafePermissions()); got != "use,retrieve" {
		t.Fatalf("the default must be what the column defaults to, got %q", got)
	}
}

// TestGrantPermits pins the one reading every door shares: a direct target
// grant (nil) admits use and retrieve but never approve; a membership admits
// exactly what it names; "reach" is any target access at all.
func TestGrantPermits(t *testing.T) {
	cases := []struct {
		name   string
		perms  []string
		action string
		want   bool
	}{
		{"direct grant uses", nil, store.SafePermUse, true},
		{"direct grant retrieves", nil, store.SafePermRetrieve, true},
		{"direct grant never approves", nil, store.SafePermApprove, false},
		{"direct grant reaches", nil, store.AccessReach, true},
		{"use-only member uses", []string{"use"}, store.SafePermUse, true},
		{"use-only member does not retrieve", []string{"use"}, store.SafePermRetrieve, false},
		{"retrieve-only member reaches", []string{"retrieve"}, store.AccessReach, true},
		{"approve-only member approves", []string{"approve"}, store.SafePermApprove, true},
		{"approve-only member does not reach", []string{"approve"}, store.AccessReach, false},
		{"empty member set confers nothing", []string{}, store.SafePermUse, false},
	}
	for _, tc := range cases {
		if got := store.GrantPermits(tc.perms, tc.action); got != tc.want {
			t.Errorf("%s: GrantPermits(%v, %q) = %v, want %v", tc.name, tc.perms, tc.action, got, tc.want)
		}
	}
}
