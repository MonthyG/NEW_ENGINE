package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/manager/alert"
	"hostinginside/waf/manager/backup"
	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/crsplugins"
	"hostinginside/waf/manager/store"
)

// newOpsAPI is newTestAPI with a rule sets directory holding CRS 4.30.0 and
// an unpacked-but-incomplete 4.31.0, and backups on.
func newOpsAPI(t *testing.T) (http.Handler, *fakeLoader, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "waf.db"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	sets := filepath.Join(dir, "rulesets")
	for _, f := range []string{"4.30.0/crs-setup.conf.example", "4.30.0/rules/REQUEST-901-INITIALIZATION.conf", "4.31.0/crs-setup.conf.example"} {
		require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(sets, f)), 0o755))
		require.NoError(t, os.WriteFile(filepath.Join(sets, f), nil, 0o644))
	}
	fl := &fakeLoader{}
	a := New(st, fl, compile.Options{AdminListen: "127.0.0.1:2019", HTTPPort: 80, HTTPSPort: 443, EventLog: "events.log",
		ChallengeSecret: base64.StdEncoding.EncodeToString(make([]byte, 32))}, []string{testKey})
	a.SetOps(Ops{RulesetsDir: sets, PluginsDir: "/data/crs-plugins", Backups: &backup.Backups{Store: st, Dir: filepath.Join(dir, "backups")},
		Notifier: &alert.Notifier{Store: st, Host: "edge"}})
	return a.Handler(), fl, sets
}

func TestRulesetSwitchAndRollback(t *testing.T) {
	h, fl, sets := newOpsAPI(t)
	assert.Equal(t, http.StatusConflict, do(t, h, "PUT", "/api/v1/rulesets/active", `{"version":"4.30.0"}`).Code,
		"with no WAF site the engine can't check the rules")
	createSite(t, h, minimalDoc)

	var list rulesetsView
	decodeBody(t, do(t, h, "GET", "/api/v1/rulesets", ""), &list)
	require.Len(t, list.Items, 2, "the incomplete 4.31.0 is not offered")
	assert.True(t, list.Items[0].Active)
	assert.Equal(t, Ruleset, list.Items[0].Name)
	assert.Equal(t, "4.30.0", list.Items[1].Version)

	rec := do(t, h, "PUT", "/api/v1/rulesets/active", `{"version":"4.30.0"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	b, _ := json.Marshal(fl.configs[len(fl.configs)-1])
	assert.Contains(t, string(b), "Include "+filepath.ToSlash(sets)+"/4.30.0/rules/*.conf")
	assert.NotContains(t, string(b), "@owasp_crs")
	var sys systemView
	decodeBody(t, do(t, h, "GET", "/api/v1/system", ""), &sys)
	assert.Equal(t, "CRS 4.30.0", sys.Ruleset)

	// the engine refuses the built-in rules: the setting rolls back
	fl.err = &caddyclient.LoadError{Status: 400, Body: "cannot parse"}
	assert.Equal(t, http.StatusBadGateway, do(t, h, "PUT", "/api/v1/rulesets/active", `{"version":""}`).Code)
	decodeBody(t, do(t, h, "GET", "/api/v1/system", ""), &sys)
	assert.Equal(t, "CRS 4.30.0", sys.Ruleset)
	fl.err = nil

	for _, v := range []string{"4.31.0", "../4.30.0", "9.9.9"} {
		assert.Equal(t, http.StatusBadRequest, do(t, h, "PUT", "/api/v1/rulesets/active", `{"version":"`+v+`"}`).Code, v)
	}
}

func TestBackupRoutes(t *testing.T) {
	h, _, _ := newOpsAPI(t)
	rec := do(t, h, "POST", "/api/v1/backups", "")
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var f backup.File
	decodeBody(t, rec, &f)
	var list []backup.File
	decodeBody(t, do(t, h, "GET", "/api/v1/backups", ""), &list)
	require.Len(t, list, 1)
	assert.Equal(t, f.Name, list[0].Name)

	rec = do(t, h, "GET", "/api/v1/backups/"+f.Name, "")
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Disposition"), f.Name)
	assert.Equal(t, "SQLite format 3\x00", rec.Body.String()[:16])
	for _, bad := range []string{"waf.db", "..%2Fwaf.db", "waf-20261027-000000.db"} {
		assert.Equal(t, http.StatusNotFound, do(t, h, "GET", "/api/v1/backups/"+bad, "").Code, bad)
	}
	assert.Equal(t, http.StatusUnauthorized, doKey(t, h, "GET", "/api/v1/backups/"+f.Name, "", "").Code)
}

func TestAlertSettings(t *testing.T) {
	h, _, _ := newOpsAPI(t)
	assert.Equal(t, http.StatusBadRequest, do(t, h, "PUT", "/api/v1/alerts", `{"webhook_url":"file:///etc/passwd"}`).Code)
	assert.Equal(t, http.StatusBadRequest, do(t, h, "POST", "/api/v1/alerts/test", "").Code, "no webhook yet")
	rec := do(t, h, "PUT", "/api/v1/alerts", `{"webhook_url":" https://hooks.example.test/x ","heartbeat_url":""}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var v alertsView
	decodeBody(t, rec, &v)
	assert.Equal(t, "https://hooks.example.test/x", v.WebhookURL)
}

func TestAppProfiles(t *testing.T) {
	h, fl, _ := newOpsAPI(t)
	var apps []crsplugins.App
	decodeBody(t, do(t, h, "GET", "/api/v1/apps", ""), &apps)
	require.Len(t, apps, len(crsplugins.Catalog))
	assert.Equal(t, "wordpress", apps[0].Key)

	id := createSite(t, h, `{"domains":["blog.example.com"],"upstreams":["10.0.0.5:8080"],"waf":{"apps":["wordpress"]}}`)
	b, _ := json.Marshal(fl.configs[len(fl.configs)-1])
	assert.Contains(t, string(b), "Include /data/crs-plugins/wordpress/wordpress-rule-exclusions-before.conf")
	var v siteView
	decodeBody(t, do(t, h, "GET", "/api/v1/sites/"+id, ""), &v)
	assert.Equal(t, []string{"wordpress"}, v.Resolved.WAF.Apps)
	assert.Equal(t, http.StatusBadRequest, do(t, h, "PATCH", "/api/v1/sites/"+id, `{"waf":{"apps":["joomla"]}}`).Code)
	assert.Equal(t, http.StatusBadRequest, do(t, h, "PATCH", "/api/v1/sites/"+id, `{"waf":{"apps":["wordpress","wordpress"]}}`).Code)

	// a manager without a plugins directory offers none and refuses them
	h2, _ := newTestAPI(t)
	decodeBody(t, do(t, h2, "GET", "/api/v1/apps", ""), &apps)
	assert.Empty(t, apps)
	assert.Equal(t, http.StatusBadRequest, do(t, h2, "POST", "/api/v1/sites", `{"domains":["b.example.com"],"upstreams":["10.0.0.5:8080"],"waf":{"apps":["wordpress"]}}`).Code)
}
