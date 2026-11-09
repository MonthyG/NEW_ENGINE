package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

const siteID = "s_aabbccddeeff"

// provision provisions a and swaps in an observable logger.
func provision(t *testing.T, a *Access) *observer.ObservedLogs {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	a.SiteID = siteID
	require.NoError(t, a.Provision(ctx))
	core, logs := observer.New(zap.InfoLevel)
	a.logger = zap.New(core)
	return logs
}

// serve runs one request from ip and returns the handler error, whether next
// was called and the skip var.
func serve(a *Access, ip, method, target string) (err error, nextCalled bool, skip any) {
	r := httptest.NewRequest(method, target, nil)
	r.RemoteAddr = ip + ":1234"
	vars := map[string]any{}
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		nextCalled = true
		return nil
	})
	err = a.ServeHTTP(httptest.NewRecorder(), r, next)
	return err, nextCalled, vars[SkipVar]
}

func requireStatus(t *testing.T, err error, code int) {
	t.Helper()
	var he caddyhttp.HandlerError
	require.ErrorAs(t, err, &he)
	assert.Equal(t, code, he.StatusCode)
}

func eventTypes(logs *observer.ObservedLogs) []string {
	var out []string
	for _, e := range logs.All() {
		out = append(out, e.ContextMap()["event"].(string))
	}
	return out
}

func TestModuleOrder(t *testing.T) {
	a := &Access{
		AllowIPs: []string{"10.0.0.1"},
		BlockIPs: []string{"10.0.0.1", "10.0.0.2"},
		Rules: []Rule{
			{Action: "block", Match: Match{PathPrefix: "/admin", NotIP: []string{"10.0.0.9"}}},
			{Action: "allow", Match: Match{PathPrefix: "/public"}},
		},
	}
	logs := provision(t, a)

	// in both allow and block: allowed, next called, skip set
	err, called, skip := serve(a, "10.0.0.1", "GET", "/admin")
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "true", skip)
	assert.Empty(t, logs.All())

	// block_ips
	err, called, _ = serve(a, "10.0.0.2", "GET", "/")
	requireStatus(t, err, 403)
	assert.False(t, called)
	assert.Equal(t, []string{"ip_block"}, eventTypes(logs))

	// rule block
	logs.TakeAll()
	err, called, _ = serve(a, "10.0.0.3", "GET", "/admin")
	requireStatus(t, err, 403)
	assert.False(t, called)
	assert.Equal(t, []string{"rule_block"}, eventTypes(logs))

	// rule allow
	logs.TakeAll()
	err, called, skip = serve(a, "10.0.0.3", "GET", "/public/x")
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "true", skip)
	assert.Equal(t, []string{"allowed_by_rule"}, eventTypes(logs))

	// no match
	err, called, skip = serve(a, "10.0.0.3", "GET", "/shop")
	assert.NoError(t, err)
	assert.True(t, called)
	assert.Nil(t, skip)
}

func TestUnparseableClientIPStillRunsNonIPRules(t *testing.T) {
	a := &Access{
		BlockIPs: []string{"0.0.0.0/0"},
		Rules:    []Rule{{Action: "block", Match: Match{PathPrefix: "/admin"}}},
	}
	logs := provision(t, a)
	r := httptest.NewRequest("GET", "/admin", nil)
	r.RemoteAddr = "garbage"
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
	called := false
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { called = true; return nil })
	err := a.ServeHTTP(httptest.NewRecorder(), r, next)
	requireStatus(t, err, 403)
	assert.False(t, called)
	assert.Equal(t, []string{"rule_block"}, eventTypes(logs))
}

func TestUnparseableIPNotIPFailsClosed(t *testing.T) {
	a := &Access{Rules: []Rule{
		{Action: "block", Match: Match{PathPrefix: "/admin", NotIP: []string{"1.2.3.4"}}},
		{Action: "allow", Match: Match{PathPrefix: "/public", NotIP: []string{"1.2.3.4"}}},
	}}
	provision(t, a)
	run := func(target string) (error, any) {
		r := httptest.NewRequest("GET", target, nil)
		r.RemoteAddr = "garbage"
		vars := map[string]any{}
		r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, vars))
		next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
		return a.ServeHTTP(httptest.NewRecorder(), r, next), vars[SkipVar]
	}
	err, _ := run("/admin")
	requireStatus(t, err, 403)
	err, skip := run("/public")
	assert.NoError(t, err)
	assert.Nil(t, skip)
}

func TestGeoBlocking(t *testing.T) {
	countries := map[string]string{"1.1.1.1": "CN", "2.2.2.2": "US", "3.3.3.3": "de"}
	a := &Access{BlockCountries: []string{"cn"}, AllowCountries: []string{"US", "CN"}}
	logs := provision(t, a)
	a.countryOf = func(ip netip.Addr) string { return countries[ip.String()] }

	err, _, _ := serve(a, "1.1.1.1", "GET", "/") // blocked list wins over allow list
	requireStatus(t, err, 403)
	assert.Equal(t, []string{"geo_block"}, eventTypes(logs))

	err, called, _ := serve(a, "2.2.2.2", "GET", "/")
	assert.NoError(t, err)
	assert.True(t, called)

	err, _, _ = serve(a, "3.3.3.3", "GET", "/") // known, not in allow list
	requireStatus(t, err, 403)

	err, _, _ = serve(a, "9.9.9.9", "GET", "/") // unknown public address: not on the allow list
	requireStatus(t, err, 403)

	err, called, _ = serve(a, "10.1.2.3", "GET", "/") // private addresses have no country and pass
	assert.NoError(t, err)
	assert.True(t, called)

	b := &Access{BlockCountries: []string{"CN"}} // a block list alone lets unknown through
	provision(t, b)
	b.countryOf = func(netip.Addr) string { return "" }
	err, called, _ = serve(b, "9.9.9.9", "GET", "/")
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestCountryRule(t *testing.T) {
	a := &Access{
		Rules: []Rule{{Action: "block", Match: Match{Country: []string{"RU"}, PathPrefix: "/login"}}},
	}
	provision(t, a)
	a.countryOf = func(netip.Addr) string { return "RU" }
	err, _, _ := serve(a, "7.7.7.7", "GET", "/login")
	requireStatus(t, err, 403)
	err, called, _ := serve(a, "7.7.7.7", "GET", "/")
	assert.NoError(t, err)
	assert.True(t, called)
}

func TestCountryWithoutDBInvalid(t *testing.T) {
	assert.Error(t, (&Access{SiteID: siteID, BlockCountries: []string{"CN"}}).Validate())
	assert.Error(t, (&Access{SiteID: siteID, Rules: []Rule{{Action: "block", Match: Match{Country: []string{"CN"}}}}}).Validate())
	assert.NoError(t, (&Access{SiteID: siteID, BlockCountries: []string{"CN"}, GeoIPDB: "x.mmdb"}).Validate())
	assert.Error(t, (&Access{}).Validate())
}

func TestBlockIPsFile(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "feed.txt")
	require.NoError(t, os.WriteFile(good, []byte("# feed\n203.0.113.0/24\n\n"), 0o600))
	a := &Access{BlockIPsFile: good}
	logs := provision(t, a)
	err, called, _ := serve(a, "203.0.113.9", "GET", "/")
	requireStatus(t, err, 403)
	assert.False(t, called)
	assert.Equal(t, []string{"ip_block"}, eventTypes(logs))

	bad := filepath.Join(dir, "bad.txt")
	require.NoError(t, os.WriteFile(bad, []byte("# feed\n203.0.113.0/24\nnonsense\n"), 0o600))
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	err = (&Access{SiteID: siteID, BlockIPsFile: bad}).Provision(ctx)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line 3")
}
