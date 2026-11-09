package compile

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/site"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden.json")

func baseOptions() Options {
	return Options{
		AdminListen:     "127.0.0.1:2019",
		HTTPPort:        80,
		HTTPSPort:       443,
		EventLog:        "/var/log/hi-waf/events.log",
		ChallengeSecret: "c2VjcmV0",
		GeoIPDB:         "/var/lib/hi-waf/GeoLite2-Country.mmdb",
	}
}

// marshal is how goldens are written: two-space indent, no HTML escaping
// (so "<" stays readable), trailing newline.
func marshal(t *testing.T, v any) string {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	return b.String()
}

func TestDirectivesDetectAndDisabled(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		WAF: &site.WAFDoc{Mode: "detect", Paranoia: 2, Protections: map[string]bool{"java": false}}})
	d := Directives(r, "", "")
	assert.Contains(t, d, "SecRuleEngine DetectionOnly")
	assert.Contains(t, d, "tx.blocking_paranoia_level=2")
	assert.Contains(t, d, "SecRuleRemoveById 944000-944999")
	assert.Contains(t, d, "SecRuleRemoveById 950000-956999") // data_leak default off
	assert.Contains(t, d, "SecResponseBodyAccess Off")
	assert.Less(t, strings.Index(d, "id:900000"), strings.Index(d, "@owasp_crs/*.conf"))
	assert.Contains(t, d, "tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'")
	assert.Contains(t, d, "|text/plain|")
	assert.Less(t, strings.Index(d, "id:900220"), strings.Index(d, "@owasp_crs/*.conf"))
	assert.Less(t, strings.Index(d, "@owasp_crs/*.conf"), strings.Index(d, "SecRuleRemoveById"))
}

func TestDirectivesExclusions(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"}, Exclusions: []site.Exclusion{
		{RuleID: 942100, PathExact: "/search", Field: "ARGS:q"},
		{RuleID: 941160, PathPrefix: "/wp-admin/"},
		{RuleID: 942190, Field: "ARGS:text"},
		{RuleID: 932235},
	}})
	d := Directives(r, "", "")
	rules := strings.Index(d, "@owasp_crs/*.conf")
	for _, want := range []string{
		`SecRule REQUEST_FILENAME "@streq /search" "id:10100,phase:1,t:none,pass,nolog,ctl:ruleRemoveTargetById=942100;ARGS:q"`,
		`SecRule REQUEST_FILENAME "@beginsWith /wp-admin/" "id:10101,phase:1,t:none,pass,nolog,ctl:ruleRemoveById=941160"`,
	} {
		i := strings.Index(d, want)
		require.GreaterOrEqual(t, i, 0, want)
		assert.Less(t, i, rules, "a path exception runs before the rules")
	}
	for _, want := range []string{`SecRuleUpdateTargetById 942190 "!ARGS:text"`, "SecRuleRemoveById 932235"} {
		assert.Greater(t, strings.Index(d, want), rules, want)
	}
}

func TestDirectivesApps(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		WAF: &site.WAFDoc{Apps: []string{"wordpress", "phpmyadmin"}}})
	d := Directives(r, "", "/data/crs-plugins")
	rules := strings.Index(d, "Include @owasp_crs/*.conf")
	at := func(s string) int {
		i := strings.Index(d, "Include /data/crs-plugins/"+s)
		require.GreaterOrEqual(t, i, 0, s)
		return i
	}
	assert.Less(t, at("wordpress/wordpress-rule-exclusions-config.conf"), at("wordpress/wordpress-rule-exclusions-before.conf"))
	assert.Less(t, at("phpmyadmin/phpmyadmin-rule-exclusions-config.conf"), at("wordpress/wordpress-rule-exclusions-before.conf"), "every config before any before")
	assert.Less(t, at("phpmyadmin/phpmyadmin-rule-exclusions-before.conf"), rules)
	assert.Greater(t, at("phpmyadmin/phpmyadmin-rule-exclusions-after.conf"), rules)
	assert.NotContains(t, Directives(site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"}}), "", "/data/crs-plugins"), "crs-plugins")
}

func TestDirectivesInstalledRuleset(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"}})
	d := Directives(r, "/data/rulesets/4.30.0", "")
	assert.Contains(t, d, "Include @coraza.conf-recommended")
	assert.Contains(t, d, "Include /data/rulesets/4.30.0/crs-setup.conf.example")
	assert.Contains(t, d, "Include /data/rulesets/4.30.0/rules/*.conf")
	assert.NotContains(t, d, "@owasp_crs")
}

func TestDirectivesDataLeakOn(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		WAF: &site.WAFDoc{Protections: map[string]bool{"data_leak": true}}})
	d := Directives(r, "", "")
	assert.Contains(t, d, "SecRuleEngine On")
	assert.Contains(t, d, "SecResponseBodyAccess On")
	assert.NotContains(t, d, "SecRuleRemoveById")
}

// Guards spec §5 against the CRS embedded in the pinned coraza-caddy: every
// 3-digit file number covered by a protection range must exist as
// @owasp_crs/REQUEST-NNN-*.conf or RESPONSE-NNN-*.conf.
func TestProtectionRangesExistInEmbeddedCRS(t *testing.T) {
	for _, p := range site.Protections {
		for _, r := range p.IDRanges {
			lo, hi, ok := strings.Cut(r, "-")
			require.True(t, ok, r)
			from, err := strconv.Atoi(lo)
			require.NoError(t, err)
			to, err := strconv.Atoi(hi)
			require.NoError(t, err)
			for n := from / 1000; n <= to/1000; n++ {
				m, err := fs.Glob(coreruleset.FS, fmt.Sprintf("@owasp_crs/*-%d-*.conf", n))
				require.NoError(t, err)
				assert.NotEmpty(t, m, "%s: no CRS file for %d", p.Key, n)
			}
		}
	}
}

func TestConfigGolden(t *testing.T) {
	cases := []struct {
		name  string
		sites []site.Resolved
		certs map[string]site.Cert
		opt   func(*Options)
	}{
		{
			name: "auto_tls",
			sites: []site.Resolved{site.Resolve("s_aaaaaaaaaaaa", site.Doc{
				Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.1:80"},
			})},
		},
		{
			name: "plain_access_challenge",
			sites: []site.Resolved{site.Resolve("s_bbbbbbbbbbbb", site.Doc{
				Domains:   []string{"b.com"},
				Upstreams: []string{"https://10.0.0.2:443"},
				TLS:       &site.TLSDoc{Mode: "off"},
				Access: &site.AccessDoc{
					BlockIPs: []string{"1.2.3.4"},
					Rules:    []access.Rule{{Action: "block", Match: access.Match{PathPrefix: "/admin"}}},
				},
				BotChallenge: &site.ChallengeDoc{Enabled: true, Difficulty: 5},
			})},
			opt: func(o *Options) { o.TrustedProxies = []string{"10.0.0.0/8"} },
		},
		{
			name: "uploaded_cert",
			sites: []site.Resolved{site.Resolve("s_cccccccccccc", site.Doc{
				Domains: []string{"c.com"}, Upstreams: []string{"10.0.0.3:80"},
				TLS: &site.TLSDoc{Mode: "uploaded"},
			})},
			certs: map[string]site.Cert{"s_cccccccccccc": {CertPEM: "CERT", KeyPEM: "KEY"}},
			opt:   func(o *Options) { o.ACMEInternal = true },
		},
		{
			name: "waf_off",
			sites: []site.Resolved{site.Resolve("s_dddddddddddd", site.Doc{
				Domains: []string{"d.com"}, Upstreams: []string{"10.0.0.4:80"},
				WAF:       &site.WAFDoc{Mode: "off"},
				RateLimit: &site.RateLimitDoc{Error: site.Optional[ratelimit.Limit]{Set: true, Null: true}},
			})},
		},
		{
			name: "mixed_tls_plain",
			sites: []site.Resolved{
				site.Resolve("s_eeeeeeeeeeee", site.Doc{Domains: []string{"e.com"}, Upstreams: []string{"10.0.0.5:80"}}),
				site.Resolve("s_ffffffffffff", site.Doc{Domains: []string{"f.com"}, Upstreams: []string{"10.0.0.6:80"},
					TLS: &site.TLSDoc{Mode: "off"}}),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := baseOptions()
			if c.opt != nil {
				c.opt(&o)
			}
			cfg, err := Config(c.sites, c.certs, o)
			require.NoError(t, err)
			got := marshal(t, cfg)
			path := filepath.Join("testdata", c.name+".golden.json")
			if *update {
				require.NoError(t, os.WriteFile(path, []byte(got), 0o644))
				return
			}
			want, err := os.ReadFile(path)
			require.NoError(t, err)
			assert.Equal(t, strings.ReplaceAll(string(want), "\r", ""), got)
		})
	}
}

func TestUploadedWithoutCertErrors(t *testing.T) {
	r := site.Resolve("s_cccccccccccc", site.Doc{Domains: []string{"c.com"}, Upstreams: []string{"10.0.0.3:80"},
		TLS: &site.TLSDoc{Mode: "uploaded"}})
	_, err := Config([]site.Resolved{r}, nil, baseOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s_cccccccccccc")
}

func TestBlockPageEscapesHTML(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"},
		BlockPage: &site.BlockPageDoc{Title: "<script>", Message: "a & {env.SECRET}"}})
	h := blockPageHandler(t, r)
	body := h["body"].(string)
	assert.Contains(t, body, "&lt;script&gt;")
	assert.NotContains(t, body, "<script>")
	assert.Contains(t, body, "a &amp; &#123;env.SECRET&#125;")
	assert.NotContains(t, body, "{env.SECRET}")
	assert.Contains(t, body, "Event ID <code>{http.error.id}</code>")
	assert.Equal(t, "{http.error.status_code}", h["status_code"])
}

// blockPageHandler returns the handler of the site's non-429 error route.
func blockPageHandler(t *testing.T, r site.Resolved) map[string]any {
	t.Helper()
	routes := blockPages(r, []any{map[string]any{"host": []string{"a.com"}}})
	require.Len(t, routes, 2)
	return routes[1].(map[string]any)["handle"].([]any)[0].(map[string]any)
}

func TestBlockPageDefaults(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"}})
	body := blockPageHandler(t, r)["body"].(string)
	assert.Contains(t, body, "<h1>Request blocked</h1>")
	assert.Contains(t, body, "<p>Your request was blocked by the web application firewall.</p>")
}

func TestRateLimitPageMatches429First(t *testing.T) {
	r := site.Resolve("s_a", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"1.1.1.1:80"}})
	routes := blockPages(r, []any{map[string]any{"host": []string{"a.com"}}})
	m := routes[0].(map[string]any)["match"].([]any)[0].(map[string]any)
	assert.Equal(t, "{http.error.status_code} == 429", m["expression"])
	assert.Equal(t, []string{"a.com"}, m["host"])
	assert.Equal(t, true, routes[0].(map[string]any)["terminal"])
}

func TestCustomPortsAndConflicts(t *testing.T) {
	a := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.1:80"},
		Ports: []site.PortDoc{{Port: 8000}, {Port: 8443, HTTPS: true}}})
	cfg, err := Config([]site.Resolved{a}, nil, baseOptions())
	require.NoError(t, err)
	srvs := servers(t, cfg)
	require.Contains(t, srvs, "p8000")
	require.Contains(t, srvs, "p8443")
	assert.Equal(t, map[string]any{"disable": true}, srvs["p8000"].(map[string]any)["automatic_https"])
	redir := srvs["p8000"].(map[string]any)["routes"].([]any)[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	assert.Equal(t, []string{"https://{http.request.host}:8443{http.request.uri}"}, redir["headers"].(map[string]any)["Location"])

	b := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"b.com"}, Upstreams: []string{"10.0.0.2:80"},
		TLS: &site.TLSDoc{Mode: "off"}, Ports: []site.PortDoc{{Port: 8443}}})
	_, err = Config([]site.Resolved{a, b}, nil, baseOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "both HTTP and HTTPS")

	o := baseOptions()
	o.ReservedPorts = []int{8000}
	_, err = Config([]site.Resolved{a}, nil, o)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "reserved")
}

func TestMatchAllSiteIsLastAndLogsByDefault(t *testing.T) {
	all := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"*"}, Upstreams: []string{"10.0.0.1:80"},
		TLS: &site.TLSDoc{Mode: "off"}})
	named := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"b.com"}, Upstreams: []string{"10.0.0.2:80"},
		TLS: &site.TLSDoc{Mode: "off"}})
	o := baseOptions()
	o.AccessLog = "/var/log/hi-waf/access.log"
	cfg, err := Config([]site.Resolved{all, named}, nil, o)
	require.NoError(t, err)
	srv := servers(t, cfg)["plain"].(map[string]any)
	assert.Equal(t, [][]string{{"b.com"}, nil}, routeHosts(srv["routes"].([]any)))
	logs := srv["logs"].(map[string]any)
	assert.Equal(t, "s_aaaaaaaaaaaa", logs["default_logger_name"])
	assert.Equal(t, false, logs["skip_unmapped_hosts"])
	assert.Equal(t, map[string]any{"b.com": "s_bbbbbbbbbbbb"}, logs["logger_names"])
}

func TestStaticRedirectAndGlobalCert(t *testing.T) {
	st := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"a.com"}, Type: "static"})
	rd := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"b.com"}, Type: "redirect",
		Redirect: &site.RedirectDoc{URL: "https://new.example/", Code: 301, PreservePath: true},
		TLS:      &site.TLSDoc{Mode: "uploaded", CertID: "c_000000000001"}})
	_, err := Config([]site.Resolved{st}, nil, baseOptions())
	require.Error(t, err, "static needs StaticDir")

	o := baseOptions()
	o.StaticDir = "/data/static"
	cfg, err := Config([]site.Resolved{st, rd}, map[string]site.Cert{"c_000000000001": {CertPEM: "C", KeyPEM: "K"}}, o)
	require.NoError(t, err)
	out := marshal(t, cfg)
	assert.Contains(t, out, `"handler": "file_server"`)
	assert.Contains(t, out, `"root": "`+strings.ReplaceAll(filepath.Join("/data/static", "s_aaaaaaaaaaaa"), `\`, `\\`)+`"`)
	assert.Contains(t, out, `"https://new.example{http.request.uri}"`)
	assert.Contains(t, out, `"c_000000000001"`)
}

// routeHosts lists each route's host matcher (nil for the fallback route).
func routeHosts(routes []any) [][]string {
	var out [][]string
	for _, r := range routes {
		m, ok := r.(map[string]any)["match"]
		if !ok {
			out = append(out, nil)
			continue
		}
		out = append(out, m.([]any)[0].(map[string]any)["host"].([]string))
	}
	return out
}

func servers(t *testing.T, cfg map[string]any) map[string]any {
	t.Helper()
	return cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)
}

// Ruling R11: exact-domain routes come before wildcard-domain routes, so
// x.a.com reaches its own site even when *.a.com's site is listed first.
func TestExactDomainsBeforeWildcards(t *testing.T) {
	wild := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"*.a.com", "a.com"}, Upstreams: []string{"10.0.0.1:80"}})
	exact := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	cfg, err := Config([]site.Resolved{wild, exact}, nil, baseOptions())
	require.NoError(t, err)
	srv := servers(t, cfg)["waf"].(map[string]any)
	assert.Equal(t, [][]string{{"a.com"}, {"x.a.com"}, {"*.a.com"}, nil}, routeHosts(srv["routes"].([]any)))
	assert.Equal(t, [][]string{{"a.com"}, {"a.com"}, {"x.a.com"}, {"x.a.com"}, {"*.a.com"}, {"*.a.com"}},
		routeHosts(srv["errors"].(map[string]any)["routes"].([]any)))
}

// Ruling R13: the plain server redirects TLS domains itself, ordered with the
// plain sites, so a plain *.a.com can't capture a TLS x.a.com on port 80.
func TestPlainServerRedirectsBeforeWildcards(t *testing.T) {
	plain := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"*.a.com"}, Upstreams: []string{"10.0.0.1:80"},
		TLS: &site.TLSDoc{Mode: "off"}})
	secure := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	cfg, err := Config([]site.Resolved{plain, secure}, nil, baseOptions())
	require.NoError(t, err)
	srvs := servers(t, cfg)
	routes := srvs["plain"].(map[string]any)["routes"].([]any)
	assert.Equal(t, [][]string{{"x.a.com"}, {"*.a.com"}, nil}, routeHosts(routes))
	redir := routes[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	assert.Equal(t, 308, redir["status_code"])
	assert.Equal(t, []string{"https://{http.request.host}{http.request.uri}"},
		redir["headers"].(map[string]any)["Location"])
	assert.Equal(t, true, srvs["waf"].(map[string]any)["automatic_https"].(map[string]any)["disable_redirects"])
}

func TestRedirectKeepsNonDefaultHTTPSPort(t *testing.T) {
	secure := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	o := baseOptions()
	o.HTTPSPort = 8443
	cfg, err := Config([]site.Resolved{secure}, nil, o)
	require.NoError(t, err)
	routes := servers(t, cfg)["plain"].(map[string]any)["routes"].([]any)
	redir := routes[0].(map[string]any)["handle"].([]any)[0].(map[string]any)
	assert.Equal(t, []string{"https://{http.request.host}:8443{http.request.uri}"},
		redir["headers"].(map[string]any)["Location"])
}

// Ruling R14: block_ips_file is a name inside FeedsDir, never a free path.
func TestBlockIPsFileInFeedsDir(t *testing.T) {
	r := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.1:80"},
		Access: &site.AccessDoc{BlockIPsFile: "drop.txt"}})
	_, err := Config([]site.Resolved{r}, nil, baseOptions())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "s_aaaaaaaaaaaa")

	o := baseOptions()
	o.FeedsDir = "/var/lib/hi-waf/feeds"
	cfg, err := Config([]site.Resolved{r}, nil, o)
	require.NoError(t, err)
	siteRoute := servers(t, cfg)["waf"].(map[string]any)["routes"].([]any)[0].(map[string]any)
	sub := siteRoute["handle"].([]any)[0].(map[string]any)["routes"].([]any) // [0] is the loop guard
	acc := sub[1].(map[string]any)["handle"].([]any)[0].(accessHandler)
	assert.Equal(t, "hi_access", acc.Handler)
	assert.Equal(t, filepath.Join("/var/lib/hi-waf/feeds", "drop.txt"), acc.BlockIPsFile)
}

// Trusted proxies always come with strict (right-to-left) X-Forwarded-For
// parsing, so a client can't spoof an allow_ips address in the header.
func TestTrustedProxiesStrict(t *testing.T) {
	secure := site.Resolve("s_bbbbbbbbbbbb", site.Doc{Domains: []string{"x.a.com"}, Upstreams: []string{"10.0.0.2:80"}})
	cfg, err := Config([]site.Resolved{secure}, nil, baseOptions())
	require.NoError(t, err)
	for name, s := range servers(t, cfg) {
		assert.NotContains(t, s.(map[string]any), "trusted_proxies", name)
		assert.NotContains(t, s.(map[string]any), "trusted_proxies_strict", name)
	}

	o := baseOptions()
	o.TrustedProxies = []string{"10.0.0.0/8"}
	cfg, err = Config([]site.Resolved{secure}, nil, o)
	require.NoError(t, err)
	srvs := servers(t, cfg)
	require.Len(t, srvs, 2)
	for name, s := range srvs {
		m := s.(map[string]any)
		assert.Equal(t, map[string]any{"source": "static", "ranges": []string{"10.0.0.0/8"}}, m["trusted_proxies"], name)
		assert.Equal(t, 1, m["trusted_proxies_strict"], name)
	}
}

func TestLogsStreamToNetworkForAFleet(t *testing.T) {
	s := site.Resolve("s_aaaaaaaaaaaa", site.Doc{Domains: []string{"a.com"}, Upstreams: []string{"10.0.0.1:80"},
		TLS: &site.TLSDoc{Mode: "off"}})
	o := baseOptions()
	o.EventLogNet = "unix//data/events.sock"
	o.AccessLogNet = "unix//data/access.sock"
	cfg, err := Config([]site.Resolved{s}, nil, o)
	require.NoError(t, err)
	var got struct {
		Logging struct {
			Logs map[string]struct {
				Writer  map[string]any `json:"writer"`
				Include []string       `json:"include"`
			} `json:"logs"`
		} `json:"logging"`
	}
	require.NoError(t, json.Unmarshal([]byte(marshal(t, cfg)), &got))
	logs := got.Logging.Logs
	assert.Equal(t, map[string]any{"output": "net", "address": "unix//data/events.sock", "soft_start": true}, logs["hi_events_net"].Writer)
	assert.Equal(t, "file", logs["hi_events"].Writer["output"], "the local events file stays as a backup")
	assert.Equal(t, logs["hi_events"].Include, logs["hi_events_net"].Include)
	assert.Equal(t, "unix//data/access.sock", logs["hi_access"].Writer["address"])
	assert.NotNil(t, servers(t, cfg)["plain"].(map[string]any)["logs"], "sites log access with only AccessLogNet set")
}
