package access

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func matchRule(t *testing.T, rule Rule, r *http.Request, ip string) bool {
	t.Helper()
	c, err := compileRule(rule)
	require.NoError(t, err)
	return c.matches(r, netip.MustParseAddr(ip), "")
}

func TestRuleANDSemantics(t *testing.T) {
	rule := Rule{Action: "block", Match: Match{PathPrefix: "/admin", NotIP: []string{"1.2.3.4"}}}
	assert.True(t, matchRule(t, rule, httptest.NewRequest("GET", "/admin/x", nil), "5.5.5.5"))
	assert.False(t, matchRule(t, rule, httptest.NewRequest("GET", "/admin/x", nil), "1.2.3.4"))
	assert.False(t, matchRule(t, rule, httptest.NewRequest("GET", "/shop", nil), "5.5.5.5"))
}

func TestRuleHeaderQueryMethod(t *testing.T) {
	hdr := Rule{Action: "block", Match: Match{Header: &KV{Name: "User-Agent", Contains: "sqlmap"}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "sqlmap/1.7")
	assert.True(t, matchRule(t, hdr, r, "5.5.5.5"))
	r.Header.Set("User-Agent", "curl")
	assert.False(t, matchRule(t, hdr, r, "5.5.5.5"))

	q := Rule{Action: "block", Match: Match{Query: &KV{Name: "debug", Regex: "^1$"}}}
	assert.True(t, matchRule(t, q, httptest.NewRequest("GET", "/?debug=1", nil), "5.5.5.5"))
	assert.False(t, matchRule(t, q, httptest.NewRequest("GET", "/?debug=12", nil), "5.5.5.5"))
	assert.False(t, matchRule(t, q, httptest.NewRequest("GET", "/", nil), "5.5.5.5"))

	m := Rule{Action: "block", Match: Match{Method: []string{"post"}}}
	assert.True(t, matchRule(t, m, httptest.NewRequest("POST", "/", nil), "5.5.5.5"))
	assert.False(t, matchRule(t, m, httptest.NewRequest("GET", "/", nil), "5.5.5.5"))
}

func TestPathNormalisation(t *testing.T) {
	rule := Rule{Action: "block", Match: Match{PathPrefix: "/admin"}}
	for _, p := range []string{"//admin", "/./admin", "/x/../admin", "/Admin", "/ADMIN/x"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		assert.True(t, matchRule(t, rule, r, "5.5.5.5"), p)
	}
	exact := Rule{Action: "block", Match: Match{PathExact: "/Login"}}
	r := httptest.NewRequest("GET", "/", nil)
	r.URL.Path = "//login"
	assert.True(t, matchRule(t, exact, r, "5.5.5.5"))
	r.URL.Path = "/login/"
	assert.False(t, matchRule(t, exact, r, "5.5.5.5"))
}

func TestContainsCaseInsensitive(t *testing.T) {
	rule := Rule{Action: "block", Match: Match{Header: &KV{Name: "User-Agent", Contains: "sqlmap"}}}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "SQLMap/1.0")
	assert.True(t, matchRule(t, rule, r, "5.5.5.5"))
}

func TestRuleHostAndCountry(t *testing.T) {
	c, err := compileRule(Rule{Action: "block", Match: Match{Host: "Example.com", Country: []string{"cn"}}})
	require.NoError(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = "example.COM:8080"
	assert.True(t, c.matches(r, netip.MustParseAddr("5.5.5.5"), "CN"))
	assert.False(t, c.matches(r, netip.MustParseAddr("5.5.5.5"), "US"))
	assert.False(t, c.matches(r, netip.MustParseAddr("5.5.5.5"), ""))
}

func TestAllowRuleValidationRequiresAnchor(t *testing.T) {
	assert.Error(t, Rule{Action: "allow", Match: Match{Method: []string{"GET"}}}.Validate())
	assert.NoError(t, Rule{Action: "allow", Match: Match{PathPrefix: "/api"}}.Validate())
	assert.Error(t, Rule{Action: "block"}.Validate())
	assert.Error(t, Rule{Action: "deny", Match: Match{PathExact: "/"}}.Validate())

	err := Rule{Action: "block", Match: Match{PathRegex: "("}}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "match.path_regex")

	err = Rule{Action: "block", Match: Match{Header: &KV{Name: "X"}}}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "match.header")

	err = Rule{Action: "block", Match: Match{IP: []string{"bogus"}}}.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "match.ip")
}

// Ruling R16: block rules see the path a lenient backend would serve, so
// backslash and ";param" tricks still reach the block rule.
func TestBlockRuleSeesThroughPathTricks(t *testing.T) {
	rule := Rule{Action: "block", Match: Match{PathPrefix: "/admin"}}
	for _, p := range []string{`/x\..\admin`, `\admin`, "/static/..;/admin", "/admin;jsessionid=1", `/static\..;\admin/x`} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		assert.True(t, matchRule(t, rule, r, "5.5.5.5"), p)
	}
	assert.Equal(t, "/admin/", cleanPath(`/x\..\admin\`))
	assert.Equal(t, "/", cleanPath(""))
}

// Ruling R16: an allow rule never matches a raw path with ";" or a ".."
// segment, so /static/..;/admin can't skip the WAF via an allow for /static.
func TestAllowRuleRefusesAmbiguousPaths(t *testing.T) {
	rule := Rule{Action: "allow", Match: Match{PathPrefix: "/static"}}
	ok := httptest.NewRequest("GET", "/static/app.js", nil)
	assert.True(t, matchRule(t, rule, ok, "5.5.5.5"))

	for _, p := range []string{"/static/..;/admin", "/static/../admin", `/static\..\admin`, "/static/x;y", "/static/../static/a"} {
		r := httptest.NewRequest("GET", "/", nil)
		r.URL.Path = p
		assert.False(t, matchRule(t, rule, r, "5.5.5.5"), p)
	}

	// The escaped form is checked too.
	r := httptest.NewRequest("GET", "/static/%2e%2e/admin", nil)
	assert.False(t, matchRule(t, rule, r, "5.5.5.5"))
	r = httptest.NewRequest("GET", "/static/a%3Bb", nil)
	assert.False(t, matchRule(t, rule, r, "5.5.5.5"))

	// IP-anchored allow rules refuse them too.
	ipRule := Rule{Action: "allow", Match: Match{IP: []string{"5.5.5.5"}}}
	r = httptest.NewRequest("GET", "/", nil)
	r.URL.Path = "/a/../b"
	assert.False(t, matchRule(t, ipRule, r, "5.5.5.5"))
}
