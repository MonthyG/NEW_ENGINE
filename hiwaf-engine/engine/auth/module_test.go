package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func newAuth(t *testing.T) *Auth {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	require.NoError(t, err)
	a := &Auth{
		SiteID: "s_000000000001",
		Secret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		Users:  []User{{Username: "alice", PasswordHash: string(h)}},
	}
	require.NoError(t, a.setup())
	require.NoError(t, a.Validate())
	return a
}

func serve(a *Auth, r *http.Request) (*httptest.ResponseRecorder, error, bool) {
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
	w := httptest.NewRecorder()
	called := false
	err := a.ServeHTTP(w, r, caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	}))
	return w, err, called
}

func status(err error) int {
	var he caddyhttp.HandlerError
	if errors.As(err, &he) {
		return he.StatusCode
	}
	return 0
}

func TestUnauthenticatedBrowserGetsLoginPage(t *testing.T) {
	a := newAuth(t)
	req := httptest.NewRequest("GET", "/admin?x=1", nil)
	req.Header.Set("Accept", "text/html")
	w, err, called := serve(a, req)
	require.NoError(t, err)
	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), `value="/admin?x=1"`)
}

func TestUnauthenticatedAPIGets401(t *testing.T) {
	_, err, called := serve(newAuth(t), httptest.NewRequest("GET", "/api", nil))
	assert.False(t, called)
	assert.Equal(t, http.StatusUnauthorized, status(err))
}

func login(a *Auth, user, pass, ret string) (*httptest.ResponseRecorder, error) {
	form := url.Values{"username": {user}, "password": {pass}, "r": {ret}}
	req := httptest.NewRequest("POST", LoginPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "text/html")
	w, err, _ := serve(a, req)
	return w, err
}

func TestLoginFlow(t *testing.T) {
	a := newAuth(t)
	w, err := login(a, "alice", "s3cret", "/admin")
	require.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin", w.Header().Get("Location"))
	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)

	req := httptest.NewRequest("GET", "/admin", nil)
	req.AddCookie(cookies[0])
	_, err, called := serve(a, req)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestLoginWrongPasswordAndUnknownUser(t *testing.T) {
	a := newAuth(t)
	for _, c := range [][2]string{{"alice", "nope"}, {"bob", "s3cret"}} {
		w, err := login(a, c[0], c[1], "/")
		require.NoError(t, err)
		assert.Equal(t, http.StatusUnauthorized, w.Code, c[0])
		assert.Contains(t, w.Body.String(), "Wrong username or password")
		assert.Empty(t, w.Result().Cookies())
	}
}

func TestOpenRedirectBlocked(t *testing.T) {
	w, err := login(newAuth(t), "alice", "s3cret", "//evil.example")
	require.NoError(t, err)
	assert.Equal(t, "/", w.Header().Get("Location"))
}

func TestSessionExpiresAndIsSiteBound(t *testing.T) {
	a := newAuth(t)
	now := time.Now()
	v := a.session("alice", now.Add(time.Minute))
	_, ok := a.checkSession(v, now)
	assert.True(t, ok)
	_, ok = a.checkSession(v, now.Add(2*time.Minute))
	assert.False(t, ok)

	other := newAuth(t)
	other.SiteID = "s_000000000002"
	_, ok = other.checkSession(v, now)
	assert.False(t, ok)
}

func TestPasswordChangeEndsSessions(t *testing.T) {
	a := newAuth(t)
	now := time.Now()
	v := a.session("alice", now.Add(time.Minute))

	same := newAuth(t) // config reloaded, password unchanged: still signed in
	same.Users = a.Users
	require.NoError(t, same.setup())
	_, ok := same.checkSession(v, now)
	assert.True(t, ok)

	changed := newAuth(t) // new bcrypt hash for alice
	_, ok = changed.checkSession(v, now)
	assert.False(t, ok)
}

func TestValidateRejectsPlainPassword(t *testing.T) {
	a := newAuth(t)
	a.Users = []User{{Username: "x", PasswordHash: "plain"}}
	require.NoError(t, a.setup())
	assert.Error(t, a.Validate())
}
