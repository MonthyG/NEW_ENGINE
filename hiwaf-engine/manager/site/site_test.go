package site

import (
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
)

func minimal() Doc {
	return Doc{Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.5:80"}}
}

func TestOmittedVsNullRateLimit(t *testing.T) {
	var d Doc
	require.NoError(t, json.Unmarshal([]byte(`{"domains":["a.com"],"upstreams":["10.0.0.5:80"],"rate_limit":{"error":null}}`), &d))
	r := Resolve("s_aaaaaaaaaaaa", d)
	assert.Nil(t, r.Access) // access off by default
	assert.Equal(t, &ratelimit.Limit{Requests: 10, WindowSec: 60, BanSec: 1800}, r.Attack)
	assert.Nil(t, r.Error) // explicit null -> off
}

func TestOptionalRoundTrip(t *testing.T) {
	var d Doc
	require.NoError(t, json.Unmarshal([]byte(`{"rate_limit":{"error":null}}`), &d))
	out, err := json.Marshal(d)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"error":null`)
	assert.NotContains(t, string(out), `"access"`)
	assert.NotContains(t, string(out), `"attack"`)

	var d2 Doc
	require.NoError(t, json.Unmarshal(out, &d2))
	assert.True(t, d2.RateLimit.Error.Set)
	assert.True(t, d2.RateLimit.Error.Null)
	assert.False(t, d2.RateLimit.Attack.Set)

	require.NoError(t, json.Unmarshal([]byte(`{"rate_limit":{"access":{"requests":5,"window_sec":10,"ban_sec":30}}}`), &d))
	out, err = json.Marshal(d)
	require.NoError(t, err)
	assert.Contains(t, string(out), `"access":{"requests":5,"window_sec":10,"ban_sec":30}`)
}

func TestDefaults(t *testing.T) {
	r := Resolve("s_aaaaaaaaaaaa", minimal())
	assert.Equal(t, "auto", r.TLSMode)
	assert.Equal(t, "block", r.WAFMode)
	assert.Equal(t, 1, r.Paranoia)
	assert.Equal(t, 5, r.AnomalyThreshold)
	assert.Len(t, r.Protections, 12)
	for k, v := range r.Protections {
		assert.Equal(t, k != "data_leak", v, k)
	}
	assert.Equal(t, &ratelimit.Limit{Requests: 50, WindowSec: 60, BanSec: 600}, r.Error)
	assert.False(t, r.Challenge)
	assert.Equal(t, 4, r.ChallengeDifficulty)
	assert.Equal(t, "Request blocked", r.BlockTitle)
	assert.Equal(t, "Your request was blocked by the web application firewall.", r.BlockMessage)
}

func TestCatalog(t *testing.T) {
	require.Len(t, Protections, 12)
	assert.Equal(t, "sqli", Protections[0].Key)
	last := Protections[11]
	assert.Equal(t, "data_leak", last.Key)
	assert.False(t, last.Default)
	assert.Equal(t, []string{"950000-956999"}, last.IDRanges)
	assert.Len(t, Protections[10].IDRanges, 3)
}

func TestProtectionsMerge(t *testing.T) {
	var d Doc
	require.NoError(t, json.Unmarshal([]byte(`{"waf":{"protections":{"xss":false}}}`), &d))
	r := Resolve("s_x", d)
	assert.False(t, r.Protections["xss"])
	assert.True(t, r.Protections["sqli"])
}

func TestResolveNormalises(t *testing.T) {
	d := minimal()
	d.Domains = []string{"Shop.Example.COM"}
	d.Access = &AccessDoc{BlockCountries: []string{"cn", " ru "}, BlockIPsFile: "/x"}
	r := Resolve("s_x", d)
	assert.Equal(t, []string{"shop.example.com"}, r.Domains)
	assert.Equal(t, []string{"CN", "RU"}, r.BlockCountries)
	assert.Equal(t, "/x", r.BlockIPsFile)
}

func TestValidateErrorsNameField(t *testing.T) {
	cases := []struct {
		name  string
		mod   func(d *Doc)
		geo   bool
		field string
	}{
		{"bad upstream", func(d *Doc) { d.Upstreams = []string{"nohost"} }, true, "upstreams[0]"},
		{"bad port", func(d *Doc) { d.Upstreams = []string{"h:99999"} }, true, "upstreams[0]"},
		{"mixed scheme", func(d *Doc) { d.Upstreams = []string{"http://a:80", "https://b:80"} }, true, "upstreams[1]"},
		{"no upstream", func(d *Doc) { d.Upstreams = nil }, true, "upstreams"},
		{"no domain", func(d *Doc) { d.Domains = nil }, true, "domains"},
		{"bad domain", func(d *Doc) { d.Domains = []string{"a.com", "-bad.com"} }, true, "domains[1]"},
		{"long name", func(d *Doc) { d.Name = strings.Repeat("x", 65) }, true, "name"},
		{"tls mode", func(d *Doc) { d.TLS = &TLSDoc{Mode: "x"} }, true, "tls.mode"},
		{"waf mode", func(d *Doc) { d.WAF = &WAFDoc{Mode: "x"} }, true, "waf.mode"},
		{"paranoia", func(d *Doc) { d.WAF = &WAFDoc{Paranoia: 5} }, true, "waf.paranoia"},
		{"threshold", func(d *Doc) { d.WAF = &WAFDoc{AnomalyThreshold: -1} }, true, "waf.anomaly_threshold"},
		{"unknown protection", func(d *Doc) { d.WAF = &WAFDoc{Protections: map[string]bool{"foo": true}} }, true, "waf.protections.foo"},
		{"limit zero", func(d *Doc) {
			d.RateLimit = &RateLimitDoc{Access: Optional[ratelimit.Limit]{Set: true, Value: ratelimit.Limit{Requests: 5, WindowSec: 0, BanSec: 1}}}
		}, true, "rate_limit.access.window_sec"},
		{"bad ip", func(d *Doc) { d.Access = &AccessDoc{BlockIPs: []string{"nope"}} }, true, "access.block_ips"},
		{"country geo off", func(d *Doc) { d.Access = &AccessDoc{BlockCountries: []string{"CN"}} }, false, "access.block_countries"},
		{"country bad", func(d *Doc) { d.Access = &AccessDoc{AllowCountries: []string{"CHN"}} }, true, "access.allow_countries"},
		{"allow rule no anchor", func(d *Doc) {
			d.Access = &AccessDoc{Rules: []access.Rule{{Action: "allow", Match: access.Match{Method: []string{"GET"}}}}}
		}, true, "access.rules[0]"},
		{"bad action", func(d *Doc) {
			d.Access = &AccessDoc{Rules: []access.Rule{{Action: "x", Match: access.Match{PathPrefix: "/"}}}}
		}, true, "access.rules[0]"},
		{"bad regex", func(d *Doc) {
			d.Access = &AccessDoc{Rules: []access.Rule{
				{Action: "block", Match: access.Match{PathPrefix: "/a"}},
				{Action: "block", Match: access.Match{PathRegex: "["}},
			}}
		}, true, "access.rules[1].match.path_regex"},
		{"bad rule ip", func(d *Doc) {
			d.Access = &AccessDoc{Rules: []access.Rule{{Action: "block", Match: access.Match{NotIP: []string{"zzz"}}}}}
		}, true, "access.rules[0].match.not_ip"},
		{"feed path slash", func(d *Doc) { d.Access = &AccessDoc{BlockIPsFile: "/etc/passwd"} }, true, "access.block_ips_file"},
		{"feed path backslash", func(d *Doc) { d.Access = &AccessDoc{BlockIPsFile: `a\b.txt`} }, true, "access.block_ips_file"},
		{"feed path dotdot", func(d *Doc) { d.Access = &AccessDoc{BlockIPsFile: "..feed"} }, true, "access.block_ips_file"},
		{"feed path blank", func(d *Doc) { d.Access = &AccessDoc{BlockIPsFile: "  "} }, true, "access.block_ips_file"},
		{"difficulty", func(d *Doc) { d.BotChallenge = &ChallengeDoc{Enabled: true, Difficulty: 7} }, true, "bot_challenge.difficulty"},
		{"bad project", func(d *Doc) { d.Project = "alpha beta" }, true, "project"},
		{"exclusion scoring rule", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 949110}} }, true, "exclusions[0].rule_id"},
		{"exclusion set-up rule", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 901001}} }, true, "exclusions[0].rule_id"},
		{"exclusion two paths", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 942100, PathExact: "/a", PathPrefix: "/b"}} }, true, "exclusions[0]"},
		{"exclusion relative path", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 942100, PathExact: "search"}} }, true, "exclusions[0].path"},
		{"exclusion quote in path", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 942100, PathPrefix: `/a" "id:1`}} }, true, "exclusions[0].path"},
		{"exclusion unknown collection", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 942100, Field: "TX:score"}} }, true, "exclusions[0].field"},
		{"exclusion field breaks out", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 942100, Field: "ARGS:q,ctl:ruleEngine=Off"}} }, true, "exclusions[0].field"},
		{"exclusion regex key", func(d *Doc) { d.Exclusions = []Exclusion{{RuleID: 942100, Field: "ARGS:/.*/"}} }, true, "exclusions[0].field"},
		{"exclusion twice", func(d *Doc) {
			d.Exclusions = []Exclusion{{RuleID: 942100, Field: "ARGS:q"}, {RuleID: 942100, Field: "ARGS:q", Note: "again"}}
		}, true, "exclusions[1]"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := minimal()
			c.mod(&d)
			err := Validate(d, c.geo)
			require.Error(t, err)
			var ve *ValidationError
			require.True(t, errors.As(err, &ve))
			assert.Equal(t, c.field, ve.Field)
			assert.NotEmpty(t, ve.Msg)
		})
	}
}

func TestValidateAccepts(t *testing.T) {
	d := minimal()
	d.Domains = []string{"Shop.Example.com", "*.example.com"}
	d.Upstreams = []string{"https://10.0.0.5:8443", "https://app.internal:443"}
	d.WAF = &WAFDoc{Mode: "detect", Paranoia: 4, AnomalyThreshold: 10}
	d.BotChallenge = &ChallengeDoc{Enabled: true}
	d.Access = &AccessDoc{
		AllowIPs:       []string{"1.2.3.4", "10.0.0.0/8"},
		BlockCountries: []string{"cn"},
		BlockIPsFile:   "spamhaus-drop.txt",
		Rules:          []access.Rule{{Action: "allow", Match: access.Match{PathPrefix: "/health"}}},
	}
	d.Exclusions = []Exclusion{
		{RuleID: 942100, PathExact: "/search", Field: "ARGS:q", Note: "null and void"},
		{RuleID: 941160, PathPrefix: "/wp-admin/"},
		{RuleID: 942550, Field: "ARGS:json.html"},
		{RuleID: 920420},
		{RuleID: 942200, Field: "REQUEST_COOKIES:CookieConsent"},
		{RuleID: 942100, Field: "ARGS:body[0][value]"},
		{RuleID: 942100, PathExact: "/files/Laporan Keuangan.pdf"},
	}
	assert.NoError(t, Validate(d, true))
	assert.NoError(t, Validate(minimal(), false))
}

func TestValidateAllDuplicateDomainsCaseInsensitive(t *testing.T) {
	a := Resolve("s_a", Doc{Domains: []string{"Shop.Example.com"}, Upstreams: []string{"1.1.1.1:80"}})
	b := Resolve("s_b", Doc{Domains: []string{"shop.example.com"}, Upstreams: []string{"1.1.1.1:80"}})
	assert.Error(t, ValidateAll([]Resolved{a, b}))
	c := Resolve("s_c", Doc{Domains: []string{"other.example.com"}, Upstreams: []string{"1.1.1.1:80"}})
	assert.NoError(t, ValidateAll([]Resolved{a, c}))
}

func TestNewID(t *testing.T) {
	id := NewID()
	assert.Regexp(t, regexp.MustCompile(`^s_[0-9a-f]{12}$`), id)
	assert.NotEqual(t, id, NewID())
}
