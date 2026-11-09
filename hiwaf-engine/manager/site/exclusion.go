package site

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Exclusion turns one CRS rule off where it raised a false alarm: on the
// whole site, on one path, for one field, or for one field on one path.
type Exclusion struct {
	RuleID     int    `json:"rule_id"`
	PathExact  string `json:"path_exact,omitempty"`
	PathPrefix string `json:"path_prefix,omitempty"`
	Field      string `json:"field,omitempty"` // a Coraza variable: ARGS:q, REQUEST_COOKIES:consent, ...
	Note       string `json:"note,omitempty"`
}

// MaxExclusions caps a site's exceptions; each path exception is one rule
// the engine runs on every request.
const MaxExclusions = 200

// fieldRE accepts a collection and an optional key. Keys can't start with "/"
// (Coraza would read a regex) or hold characters that end a SecLang string or
// action list.
var fieldRE = regexp.MustCompile(`^(ARGS|ARGS_GET|ARGS_POST|ARGS_NAMES|ARGS_GET_NAMES|ARGS_POST_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_HEADERS|REQUEST_HEADERS_NAMES|REQUEST_BODY|REQUEST_URI|REQUEST_FILENAME|FILES|FILES_NAMES|XML)(:[^/\s"'\\,;|][^\s"'\\,;|]{0,199})?$`)

// Excludable reports whether a rule ID is one the console may switch off: an
// attack or protocol rule, not the CRS set-up or the scoring rules.
func Excludable(id int) bool {
	if id/1000 == 911 {
		return true
	}
	for _, p := range Protections {
		for _, r := range p.IDRanges {
			lo, hi, _ := strings.Cut(r, "-")
			l, _ := strconv.Atoi(lo)
			h, _ := strconv.Atoi(hi)
			if id >= l && id <= h {
				return true
			}
		}
	}
	return false
}

func validPath(p string) bool {
	if !strings.HasPrefix(p, "/") || len(p) > 512 {
		return false
	}
	for _, c := range p {
		if c == '"' || c == '\\' || unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func validateExclusions(ex []Exclusion) error {
	if len(ex) > MaxExclusions {
		return verr("exclusions", "at most %d exceptions per site", MaxExclusions)
	}
	seen := map[Exclusion]bool{}
	for i, e := range ex {
		at := fmt.Sprintf("exclusions[%d]", i)
		if !Excludable(e.RuleID) {
			return verr(at+".rule_id", "%d is not a rule that can be switched off", e.RuleID)
		}
		if e.PathExact != "" && e.PathPrefix != "" {
			return verr(at, "give path_exact or path_prefix, not both")
		}
		if p := e.PathExact + e.PathPrefix; p != "" && !validPath(p) {
			return verr(at+".path", "must start with / and hold no quotes, backslashes or control characters")
		}
		if e.Field != "" && !fieldRE.MatchString(e.Field) {
			return verr(at+".field", "must look like ARGS:name or REQUEST_COOKIES:name, got %q", e.Field)
		}
		if len(e.Note) > 200 {
			return verr(at+".note", "at most 200 characters")
		}
		k := e
		k.Note = ""
		if seen[k] {
			return verr(at, "the same exception is listed twice")
		}
		seen[k] = true
	}
	return nil
}
