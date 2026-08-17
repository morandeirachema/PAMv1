package broker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/morandeirachema/pamv1/internal/auth"
)

// schemaTool declares one required string, one optional string, an int and a
// bool — every shape ValidateArgs has to judge, in one tool.
type schemaTool struct{}

func (schemaTool) Name() string        { return "schema_tool" }
func (schemaTool) Description() string { return "a tool with a full schema" }
func (schemaTool) InputSchema() map[string]string {
	return map[string]string{"target": "string", "filter": "string?", "count": "int", "force": "bool"}
}
func (schemaTool) Capability() auth.Capability { return auth.CapCallTool }
func (schemaTool) Execute(context.Context, *auth.Principal, Args) (Result, error) {
	return Result{}, nil
}

// TestParseSchemaReadsTheOptionalMarker pins the "?" convention, since it is the
// only thing separating "the caller must send this" from "the caller may".
func TestParseSchemaReadsTheOptionalMarker(t *testing.T) {
	specs := ParseSchema(schemaTool{}.InputSchema())
	if got := specs["target"]; got.Type != "string" || !got.Required {
		t.Fatalf("target should be a required string, got %+v", got)
	}
	if got := specs["filter"]; got.Type != "string" || got.Required {
		t.Fatalf("filter should be an OPTIONAL string — the marker must not survive into the type, got %+v", got)
	}
	if got := specs["count"]; got.Type != "int" || !got.Required {
		t.Fatalf("count should be a required int, got %+v", got)
	}
}

// TestValidateArgsAcceptsWhatTheSchemaDeclares proves a well-formed call passes,
// with and without the optional argument, and that a JSON integer arriving as a
// float64 (which is how encoding/json decodes every number) counts as an int.
func TestValidateArgsAcceptsWhatTheSchemaDeclares(t *testing.T) {
	full := Args{"target": "db-01", "filter": "x", "count": float64(3), "force": true}
	if err := ValidateArgs(schemaTool{}, full); err != nil {
		t.Fatalf("a complete, well-typed call must pass: %v", err)
	}
	withoutOptional := Args{"target": "db-01", "count": float64(3), "force": false}
	if err := ValidateArgs(schemaTool{}, withoutOptional); err != nil {
		t.Fatalf("omitting an OPTIONAL argument must pass: %v", err)
	}
	// json.Number appears when a decoder is configured to preserve precision;
	// it must be judged the same way a float64 is.
	if err := ValidateArgs(schemaTool{}, Args{"target": "db-01", "count": json.Number("7"), "force": true}); err != nil {
		t.Fatalf("a json.Number integer must pass: %v", err)
	}
}

// TestValidateArgsRefusesWhatTheSchemaDoesNot covers each refusal, including the
// two that are easy to get wrong: a fractional value for an int (3.5 is not an
// integer whatever it decoded into), and a MISSING required argument, which
// without this check reached the tool as an empty string via Go's comma-ok
// assertion — silently turning "you forgot an argument" into "you asked for the
// unfiltered form".
func TestValidateArgsRefusesWhatTheSchemaDoesNot(t *testing.T) {
	cases := []struct {
		name string
		args Args
		want string
	}{
		{"undeclared argument", Args{"target": "db-01", "count": float64(1), "force": true, "shell": "cmd"}, `unknown argument "shell"`},
		{"missing required string", Args{"count": float64(1), "force": true}, `missing required argument "target"`},
		{"missing required int", Args{"target": "db-01", "force": true}, `missing required argument "count"`},
		{"string where int declared", Args{"target": "db-01", "count": "3", "force": true}, `argument "count" must be a number`},
		{"fractional int", Args{"target": "db-01", "count": 3.5, "force": true}, `argument "count" must be a whole number`},
		{"number where string declared", Args{"target": 42, "count": float64(1), "force": true}, `argument "target" must be a string`},
		{"string where bool declared", Args{"target": "db-01", "count": float64(1), "force": "yes"}, `argument "force" must be true or false`},
		{"nested object where string declared", Args{"target": map[string]any{"a": 1}, "count": float64(1), "force": true}, `argument "target" must be a string`},
		// The omission bypass surviving with one character: an empty string is
		// PRESENT as far as the policy engine is concerned — satisfying both a
		// `not_in` block-list and a `present: true` guard — while a tool with an
		// optional filter reads it as "no filter" and returns everything.
		{"empty required string", Args{"target": "", "count": float64(1), "force": true}, `argument "target" must not be empty`},
		{"empty optional string", Args{"target": "db-01", "filter": "", "count": float64(1), "force": true}, `argument "filter" must not be empty`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateArgs(schemaTool{}, c.args)
			if err == nil {
				t.Fatalf("must be refused: %v", c.args)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error containing %q, got %q", c.want, err)
			}
		})
	}
}

// TestValidateArgsIsDeterministic proves a call with several problems always
// reports the same one. An error message that changes between identical requests
// is one nobody trusts, and it makes a policy author chase the wrong argument.
func TestValidateArgsIsDeterministic(t *testing.T) {
	bad := Args{"zeta": 1, "alpha": 2, "target": 3}
	first := ValidateArgs(schemaTool{}, bad).Error()
	for i := 0; i < 50; i++ {
		if got := ValidateArgs(schemaTool{}, bad).Error(); got != first {
			t.Fatalf("same call reported two different first problems: %q then %q", first, got)
		}
	}
	if !strings.Contains(first, `"alpha"`) {
		t.Fatalf("the first problem should be the alphabetically first argument, got %q", first)
	}
}

// TestValidateArgsRefusesEverythingForAToolWithNoSchema pins the fail-closed
// reading of an empty declaration: a tool that declares no arguments accepts
// none. The alternative — treating "declares nothing" as "accepts anything" —
// would make the emptiest schema the most permissive one.
func TestValidateArgsRefusesEverythingForAToolWithNoSchema(t *testing.T) {
	ran := false
	if err := ValidateArgs(recordingTool{ran: &ran}, Args{}); err != nil {
		t.Fatalf("no arguments against no schema must pass: %v", err)
	}
	if err := ValidateArgs(recordingTool{ran: &ran}, Args{"anything": "at all"}); err == nil {
		t.Fatal("a tool that declares no arguments must accept none")
	}
}
