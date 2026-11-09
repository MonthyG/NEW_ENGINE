package api

import (
	"os"
	"strings"
	"testing"
)

func TestRulesetMatchesGoMod(t *testing.T) {
	b, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	want := "github.com/corazawaf/coraza-coreruleset/v4 v" + strings.TrimPrefix(Ruleset, "CRS ")
	if !strings.Contains(string(b), want) {
		t.Fatalf("Ruleset %q is not the version in go.mod (want a line %q)", Ruleset, want)
	}
}
