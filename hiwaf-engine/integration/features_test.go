package integration

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hostinginside/waf/engine/auth"
)

// waitIn polls path for up to 2 s until a JSON line matches pred.
func waitIn(t *testing.T, path, what string, pred func(map[string]any) bool) map[string]any {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, l := range logLines(path) {
			if pred(l) {
				return l
			}
		}
		if time.Now().After(deadline) {
			raw, _ := os.ReadFile(path)
			t.Fatalf("%s has no %s line; log:\n%s", path, what, raw)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestE2E_AccessLogTagsBlocks(t *testing.T) {
	e := startEngine(t, "s_e2e000000010", `{}`)
	if code, _ := get(t, "/"+sqliQuery, nil); code != http.StatusForbidden {
		t.Fatalf("SQLi: got %d, want 403", code)
	}
	line := waitIn(t, e.accessLog, "blocked access", func(m map[string]any) bool {
		return m["hi_action"] == "block"
	})
	if line["logger"] != "http.log.access.s_e2e000000010" {
		t.Fatalf("logger = %v, want the site's access logger", line["logger"])
	}
	if tx, _ := line["hi_tx"].(string); !strings.HasPrefix(tx, "s_e2e000000010-") {
		t.Fatalf("hi_tx = %v", line["hi_tx"])
	}
	if line["hi_type"] != "waf_block" || line["status"] != float64(403) {
		t.Fatalf("line = %v", line)
	}
}

func TestE2E_RateLimitPage(t *testing.T) {
	startEngine(t, "s_e2e000000011", `{"rate_limit":{"access":{"requests":1,"window_sec":60,"ban_sec":60}}}`)
	get(t, "/", nil)
	code, body := get(t, "/", map[string]string{"Accept": "text/html"})
	if code != http.StatusTooManyRequests || !strings.Contains(body, "Too many requests") {
		t.Fatalf("got %d %q, want 429 rate-limit page", code, body)
	}
}

func TestE2E_AuthGate(t *testing.T) {
	h, err := bcrypt.GenerateFromPassword([]byte("s3cret-pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	e := startEngine(t, "s_e2e000000012", `{"auth":{"enabled":true,"users":[{"username":"bob","password_hash":"`+string(h)+`"}]}}`)
	code, body := get(t, "/private", map[string]string{"Accept": "text/html"})
	if code != http.StatusUnauthorized || !strings.Contains(body, `name="password"`) {
		t.Fatalf("got %d, want 401 login page; body %q", code, body)
	}

	form := url.Values{"username": {"bob"}, "password": {"s3cret-pw"}, "r": {"/private"}}
	req, _ := http.NewRequest(http.MethodPost, engineURL+auth.LoginPath, strings.NewReader(form.Encode()))
	req.Host = "a.test"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", browserUA)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: got %d, want 303", resp.StatusCode)
	}
	var session string
	for _, c := range resp.Cookies() {
		if c.Name == auth.CookieName {
			session = c.Value
		}
	}
	code, body = get(t, "/private", map[string]string{"Cookie": auth.CookieName + "=" + session})
	if code != http.StatusOK || body != "upstream ok" {
		t.Fatalf("with session: got %d %q", code, body)
	}
	waitIn(t, e.eventLog, "auth_passed", isEvent("auth_passed"))
}

func TestE2E_WaitingRoom(t *testing.T) {
	startEngine(t, "s_e2e000000013", `{"waiting_room":{"enabled":true,"max_active":1}}`)
	if code, _ := get(t, "/", nil); code != http.StatusOK {
		t.Fatalf("first visitor: got %d, want 200", code)
	}
	code, body := get(t, "/", map[string]string{"Accept": "text/html"})
	if code != http.StatusServiceUnavailable || !strings.Contains(body, "queue") {
		t.Fatalf("second visitor: got %d %q, want 503 queue page", code, body)
	}
}
