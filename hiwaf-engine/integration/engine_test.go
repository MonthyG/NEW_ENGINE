// Package integration runs the real engine in-process: Caddy with the
// standard modules, coraza-caddy and the hi_* modules, loaded with a config
// compiled by manager/compile, in front of an httptest upstream.
package integration

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"

	// Caddy standard modules (reverse_proxy, static_response, subroute, ...).
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	// Coraza WAF handler (http.handlers.waf).
	_ "github.com/corazawaf/coraza-caddy/v2"

	// hi_access, hi_challenge, hi_ratelimit and admin.api.hi_bans.
	_ "hostinginside/waf/engine/access"
	_ "hostinginside/waf/engine/auth"
	_ "hostinginside/waf/engine/challenge"
	_ "hostinginside/waf/engine/ratelimit"
	_ "hostinginside/waf/engine/waitroom"

	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/site"
)

const (
	engineURL = "http://127.0.0.1:9080"
	sqliQuery = "?id=1%27%20OR%20%271%27=%271"
	// A browser User-Agent keeps CRS scanner detection (913xxx) out of the way.
	browserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)

// engine is one running Caddy instance for a test.
type engine struct {
	cfg       []byte
	accessLog string
	eventLog  string
}

// startEngine compiles siteJSON (a site.Doc) as site id with TLS off and
// domain a.test pointing at a fresh httptest upstream, and loads it into an
// in-process Caddy. Caddy is stopped when the test ends.
func startEngine(t *testing.T, id, siteJSON string) *engine {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end engine test; skipped with -short")
	}
	// Not t.TempDir: its cleanup fails the test when the log is still open
	// (see the Stop cleanup below).
	dir, err := os.MkdirTemp("", "hi-waf-e2e-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "upstream ok")
	}))
	t.Cleanup(up.Close)
	upstream := strings.TrimPrefix(up.URL, "http://")

	var doc site.Doc
	if err := json.Unmarshal([]byte(siteJSON), &doc); err != nil {
		t.Fatalf("site doc: %v", err)
	}
	doc.Domains = []string{"a.test"}
	doc.Upstreams = []string{upstream}
	doc.TLS = &site.TLSDoc{Mode: "off"}
	if err := site.Validate(doc, false); err != nil {
		t.Fatalf("validate: %v", err)
	}
	resolved := []site.Resolved{site.Resolve(id, doc)}
	if err := site.ValidateAll(resolved); err != nil {
		t.Fatalf("validate all: %v", err)
	}

	e := &engine{eventLog: filepath.Join(dir, "events.log"), accessLog: filepath.Join(dir, "access.log")}
	cfg, err := compile.Config(resolved, nil, compile.Options{
		AdminListen:     "localhost:2999",
		HTTPPort:        9080,
		HTTPSPort:       9443,
		EventLog:        e.eventLog,
		AccessLog:       e.accessLog,
		ChallengeSecret: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)),
	})
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	// Don't overwrite the real autosave.json that `hi-waf run --resume` reads.
	cfg["admin"].(map[string]any)["config"] = map[string]any{"persist": false}
	if e.cfg, err = json.Marshal(cfg); err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := caddy.Load(e.cfg, true); err != nil {
		t.Fatalf("caddy load: %v\nconfig: %s", err, e.cfg)
	}
	t.Cleanup(func() {
		if err := caddy.Stop(); err != nil {
			t.Logf("caddy stop: %v", err)
		}
		// Best effort: Caddy keeps a file log writer open for the life of the
		// process (its refcount survives Stop and config swaps), so on Windows
		// the log can't be deleted until the test binary exits.
		_ = os.RemoveAll(dir)
	})
	return e
}

// reload loads the same config again, forcing Caddy to re-provision it.
func (e *engine) reload(t *testing.T) {
	t.Helper()
	if err := caddy.Load(e.cfg, true); err != nil {
		t.Fatalf("caddy reload: %v", err)
	}
}

// get sends a GET for path (with query) to the engine with Host a.test.
func get(t *testing.T, path string, header map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, engineURL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "a.test"
	req.Header.Set("User-Agent", browserUA)
	req.Header.Set("Accept", "*/*")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// logLines decodes every JSON line of the event log.
func logLines(path string) []map[string]any {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []map[string]any
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) == nil {
			out = append(out, m)
		}
	}
	return out
}

func isEvent(typ string) func(map[string]any) bool {
	return func(m map[string]any) bool { return m["msg"] == "hi_event" && m["event"] == typ }
}

// hasText matches a line any of whose string values contains s (coraza
// puts the matched rule, e.g. `[id "942100"]`, in its message).
func hasText(s string) func(map[string]any) bool {
	return func(m map[string]any) bool {
		for _, v := range m {
			if str, ok := v.(string); ok && strings.Contains(str, s) {
				return true
			}
		}
		return false
	}
}

func anyLine(lines []map[string]any, pred func(map[string]any) bool) bool {
	for _, l := range lines {
		if pred(l) {
			return true
		}
	}
	return false
}

// waitLog polls the event log for up to 2 s until a line matches pred, since
// the log writer may lag behind the response.
func (e *engine) waitLog(t *testing.T, what string, pred func(map[string]any) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if anyLine(logLines(e.eventLog), pred) {
			return
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(e.eventLog)
			t.Fatalf("event log has no %s line; log:\n%s", what, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestE2E_SQLiBlockedAndEventLogged(t *testing.T) {
	e := startEngine(t, "s_e2e000000001", `{}`)

	if code, _ := get(t, "/", nil); code != http.StatusOK {
		t.Fatalf("clean request: got %d, want 200", code)
	}
	if code, _ := get(t, "/"+sqliQuery, nil); code != http.StatusForbidden {
		t.Fatalf("SQLi: got %d, want 403", code)
	}
	e.waitLog(t, "waf_block", isEvent("waf_block"))
	e.waitLog(t, `coraza [id "942`, hasText(`[id "942`))
}

func TestE2E_DetectModePassesButLogs(t *testing.T) {
	e := startEngine(t, "s_e2e000000002", `{"waf":{"mode":"detect"}}`)

	code, body := get(t, "/"+sqliQuery, nil)
	if code != http.StatusOK || body != "upstream ok" {
		t.Fatalf("SQLi in detect mode: got %d %q, want 200 from upstream", code, body)
	}
	e.waitLog(t, `coraza [id "942`, hasText(`[id "942`))
	if anyLine(logLines(e.eventLog), isEvent("waf_block")) {
		t.Fatal("detect mode logged a waf_block event")
	}
}

func TestE2E_AccessLimitBansAndSurvivesReload(t *testing.T) {
	e := startEngine(t, "s_e2e000000003",
		`{"rate_limit":{"access":{"requests":3,"window_sec":60,"ban_sec":60}}}`)

	for i := 1; i <= 3; i++ {
		if code, _ := get(t, "/", nil); code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i, code)
		}
	}
	if code, _ := get(t, "/", nil); code != http.StatusTooManyRequests {
		t.Fatalf("request 4: got %d, want 429", code)
	}
	e.waitLog(t, "rate_limit_ban", isEvent("rate_limit_ban"))

	e.reload(t)
	if code, _ := get(t, "/", nil); code != http.StatusTooManyRequests {
		t.Fatalf("after reload: got %d, want 429 (ban must survive a reload)", code)
	}
}

func TestE2E_RuleBlockAndAllowSkipsWAF(t *testing.T) {
	e := startEngine(t, "s_e2e000000004", `{"access":{"rules":[
		{"action":"block","match":{"path_prefix":"/admin"}},
		{"action":"allow","match":{"path_prefix":"/webhook"}}
	]}}`)

	if code, _ := get(t, "/admin/login", nil); code != http.StatusForbidden {
		t.Fatalf("/admin: got %d, want 403", code)
	}
	e.waitLog(t, "rule_block", isEvent("rule_block"))

	code, body := get(t, "/webhook"+sqliQuery, nil)
	if code != http.StatusOK || body != "upstream ok" {
		t.Fatalf("SQLi to allowed /webhook: got %d %q, want 200 from upstream", code, body)
	}
	e.waitLog(t, "allowed_by_rule", isEvent("allowed_by_rule"))

	// The allow rule is scoped: the same payload elsewhere is still blocked.
	if code, _ := get(t, "/"+sqliQuery, nil); code != http.StatusForbidden {
		t.Fatalf("SQLi to /: got %d, want 403", code)
	}
}

func TestE2E_ChallengeServedToBrowser(t *testing.T) {
	startEngine(t, "s_e2e000000005", `{"bot_challenge":{"enabled":true}}`)

	code, body := get(t, "/", map[string]string{"Accept": "text/html,application/xhtml+xml"})
	if code != http.StatusOK || !strings.Contains(body, "/.hi-waf/verify") {
		t.Fatalf("browser request: got %d, want 200 challenge page containing /.hi-waf/verify; body:\n%s", code, body)
	}
	if code, _ := get(t, "/", map[string]string{"Accept": "application/json"}); code != http.StatusForbidden {
		t.Fatalf("non-browser request: got %d, want 403", code)
	}
}
