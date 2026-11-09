package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/store"
)

func newConsoleAPI(t *testing.T) (http.Handler, *fakeLoader, *store.Store, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "waf.db"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	pw, err := EnsureAdmin(context.Background(), st)
	require.NoError(t, err)
	require.NotEmpty(t, pw)
	again, err := EnsureAdmin(context.Background(), st)
	require.NoError(t, err)
	assert.Empty(t, again, "admin is created once")
	fl := &fakeLoader{}
	opt := compile.Options{AdminListen: "127.0.0.1:2019", HTTPPort: 80, HTTPSPort: 443, EventLog: "events.log",
		ChallengeSecret: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	return New(st, fl, opt, nil).Handler(), fl, st, pw
}

func loginCookie(t *testing.T, h http.Handler, user, pw, totp string) (*httptest.ResponseRecorder, *http.Cookie) {
	t.Helper()
	body, _ := json.Marshal(loginReq{Username: user, Password: pw, TOTP: totp})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(string(body)))
	req.RemoteAddr = "192.0.2.1:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	for _, c := range rec.Result().Cookies() {
		if c.Name == SessionCookie {
			return rec, c
		}
	}
	return rec, nil
}

func withCookie(h http.Handler, ck *http.Cookie, method, path, body string, csrf bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.AddCookie(ck)
	if csrf {
		req.Header.Set(CSRFHeader, csrfValue)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestLoginSessionAndCSRF(t *testing.T) {
	h, _, _, pw := newConsoleAPI(t)
	rec, ck := loginCookie(t, h, "admin", "wrong", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Nil(t, ck)

	rec, ck = loginCookie(t, h, "admin", pw, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	require.NotNil(t, ck)
	assert.True(t, ck.HttpOnly)
	assert.Equal(t, http.SameSiteStrictMode, ck.SameSite)

	assert.Equal(t, http.StatusOK, withCookie(h, ck, "GET", "/api/v1/sites", "", false).Code)
	assert.Equal(t, http.StatusForbidden, withCookie(h, ck, "POST", "/api/v1/sites", minimalDoc, false).Code,
		"session writes need the CSRF header")
	assert.Equal(t, http.StatusCreated, withCookie(h, ck, "POST", "/api/v1/sites", minimalDoc, true).Code)

	assert.Equal(t, http.StatusNoContent, withCookie(h, ck, "POST", "/api/v1/auth/logout", "", true).Code)
	assert.Equal(t, http.StatusUnauthorized, withCookie(h, ck, "GET", "/api/v1/sites", "", false).Code)
}

func TestLoginLockout(t *testing.T) {
	h, _, _, pw := newConsoleAPI(t)
	for i := 0; i < maxFailures; i++ {
		rec, _ := loginCookie(t, h, "admin", "nope", "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	}
	rec, _ := loginCookie(t, h, "admin", pw, "")
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "locked even with the right password")
}

func TestLoginLimitPerIPv6Block(t *testing.T) {
	h, _, _, pw := newConsoleAPI(t)
	try := func(addr, user, pass string) int {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
		req.RemoteAddr = addr
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	// a new address per guess inside one /64 is still one client
	for i := 0; i < maxFailures; i++ {
		assert.Equal(t, http.StatusUnauthorized, try(fmt.Sprintf("[2001:db8::%x]:4000", i+1), "admin", "nope"))
	}
	assert.Equal(t, http.StatusTooManyRequests, try("[2001:db8::ffff]:4000", "admin", pw))
	assert.Equal(t, http.StatusOK, try("[2001:db8:0:1::1]:4000", "admin", pw), "the next /64 is another client")
}

func TestLoginLimiterForgetsOldKeys(t *testing.T) {
	l := newLoginLimiter()
	old := time.Now().Add(-2 * failureWindow)
	for i := 0; i < 1023; i++ { // one below the first sweep
		l.failed(fmt.Sprintf("user:x%d", i), old)
	}
	l.failed("user:fresh", time.Now()) // the 1024th key triggers the sweep
	assert.Len(t, l.fail, 1, "keys with no recent failure are swept")
	assert.True(t, l.blocked("user:fresh", time.Now(), 1), "recent failures are kept")
}

func TestLoginLimitPerAccount(t *testing.T) {
	h, _, _, pw := newConsoleAPI(t)
	for i := 0; i < maxUserFails; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"Admin","password":"nope"}`))
		req.RemoteAddr = fmt.Sprintf("198.51.%d.%d:4000", i/250, i%250+1)
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"`+pw+`"}`))
	req.RemoteAddr = "203.0.113.9:4000"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusTooManyRequests, rec.Code, "guesses spread over many addresses still lock the account")
}

func TestTOTPFlow(t *testing.T) {
	h, _, _, pw := newConsoleAPI(t)
	_, ck := loginCookie(t, h, "admin", pw, "")
	rec := withCookie(h, ck, "POST", "/api/v1/auth/totp/setup", "", true)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var setup totpSetupView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &setup))
	assert.Contains(t, setup.URL, "otpauth://totp/")

	code, err := totpCode(setup.Secret, uint64(time.Now().Unix()/30))
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, withCookie(h, ck, "POST", "/api/v1/auth/totp/enable", `{"code":"000000"}`, true).Code)
	assert.Equal(t, http.StatusNoContent, withCookie(h, ck, "POST", "/api/v1/auth/totp/enable", `{"code":"`+code+`"}`, true).Code)

	rec, ck2 := loginCookie(t, h, "admin", pw, "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "totp_required")
	assert.Nil(t, ck2)
	rec, ck2 = loginCookie(t, h, "admin", pw, code)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, ck2)
}

func TestTokensAuthenticate(t *testing.T) {
	h, _, _, pw := newConsoleAPI(t)
	_, ck := loginCookie(t, h, "admin", pw, "")
	rec := withCookie(h, ck, "POST", "/api/v1/tokens", `{"name":"ci"}`, true)
	require.Equal(t, http.StatusCreated, rec.Code)
	var tv tokenView
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tv))
	assert.True(t, strings.HasPrefix(tv.Token, tokenPrefix))
	assert.Equal(t, http.StatusOK, doKey(t, h, "GET", "/api/v1/sites", "", "Bearer "+tv.Token).Code)
	assert.Equal(t, http.StatusNoContent, withCookie(h, ck, "DELETE", "/api/v1/tokens/"+tv.ID, "", true).Code)
	assert.Equal(t, http.StatusUnauthorized, doKey(t, h, "GET", "/api/v1/sites", "", "Bearer "+tv.Token).Code)
}

func TestAuthUsersHashedKeptAndHidden(t *testing.T) {
	h, fl := newTestAPI(t)
	id := createSite(t, h, `{"domains":["a.example.com"],"upstreams":["10.0.0.5:80"],
		"auth":{"enabled":true,"users":[{"username":"bob","password":"hunter22"}]}}`)
	rec := do(t, h, "GET", "/api/v1/sites/"+id, "")
	assert.NotContains(t, rec.Body.String(), "hunter22")
	assert.NotContains(t, rec.Body.String(), "$2a$")

	// PATCH without a password keeps bob's hash; the engine config still has it.
	rec = do(t, h, "PATCH", "/api/v1/sites/"+id, `{"name":"renamed"}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	cfg, _ := json.Marshal(fl.configs[len(fl.configs)-1])
	assert.Contains(t, string(cfg), `"hi_auth"`)
	assert.Contains(t, string(cfg), `$2a$`)

	// PUT resending bob without a password also keeps the hash.
	rec = do(t, h, "PUT", "/api/v1/sites/"+id, `{"domains":["a.example.com"],"upstreams":["10.0.0.5:80"],
		"auth":{"enabled":true,"users":[{"username":"bob"}]}}`)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	// A new user without a password is rejected.
	rec = do(t, h, "PUT", "/api/v1/sites/"+id, `{"domains":["a.example.com"],"upstreams":["10.0.0.5:80"],
		"auth":{"enabled":true,"users":[{"username":"eve"}]}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestIPGroupsAndGlobalRulesCompile(t *testing.T) {
	h, fl := newTestAPI(t)
	rec := do(t, h, "POST", "/api/v1/ip-groups", `{"name":"office","ips":["203.0.113.0/24"]}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var g struct{ ID string }
	decodeBody(t, rec, &g)
	id := createSite(t, h, `{"domains":["a.example.com"],"upstreams":["10.0.0.5:80"],"access":{"allow_groups":["`+g.ID+`"]}}`)
	cfg, _ := json.Marshal(fl.configs[len(fl.configs)-1])
	assert.Contains(t, string(cfg), "203.0.113.0/24")

	rec = do(t, h, "POST", "/api/v1/rules", `{"name":"no-admin","enabled":true,"action":"block","sites":["`+id+`"],
		"match":{"path_prefix":"/wp-admin"}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	cfg, _ = json.Marshal(fl.configs[len(fl.configs)-1])
	assert.Contains(t, string(cfg), `"name":"no-admin"`)

	// The group can't be deleted while a site uses it.
	assert.Equal(t, http.StatusConflict, do(t, h, "DELETE", "/api/v1/ip-groups/"+g.ID, "").Code)
	// A site can't reference a missing group.
	rec = do(t, h, "POST", "/api/v1/sites", `{"domains":["b.example.com"],"upstreams":["10.0.0.5:80"],"access":{"block_groups":["g_000000000000"]}}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestCleanAdminNote(t *testing.T) {
	ctx := context.Background()
	_, _, st, pw := newConsoleAPI(t)
	note := filepath.Join(t.TempDir(), "initial-admin.txt")
	gone, err := CleanAdminNote(ctx, st, note)
	require.NoError(t, err)
	assert.False(t, gone, "no file, nothing to do")

	require.NoError(t, os.WriteFile(note, []byte("Console user: admin\nPassword: "+pw+"\n"), 0o600))
	gone, err = CleanAdminNote(ctx, st, note)
	require.NoError(t, err)
	assert.False(t, gone, "the password still works, so the file stays")
	assert.FileExists(t, note)

	_, err = ResetAdmin(ctx, st)
	require.NoError(t, err)
	gone, err = CleanAdminNote(ctx, st, note)
	require.NoError(t, err)
	assert.True(t, gone, "the password changed")
	assert.NoFileExists(t, note)
}
