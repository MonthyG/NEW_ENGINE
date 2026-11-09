package challenge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newChallenge(t *testing.T) *Challenge {
	t.Helper()
	c := &Challenge{
		SiteID:     testSite,
		Secret:     "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=",
		Difficulty: 2,
	}
	require.NoError(t, c.setup())
	require.NoError(t, c.Validate())
	return c
}

// serve runs r from ip and returns the recorder, handler error and whether
// next was called.
func serve(c *Challenge, ip string, r *http.Request) (*httptest.ResponseRecorder, error, bool) {
	r.RemoteAddr = ip + ":4321"
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
	w := httptest.NewRecorder()
	called := false
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error {
		called = true
		return nil
	})
	err := c.ServeHTTP(w, r, next)
	return w, err, called
}

func statusOf(err error) int {
	var he caddyhttp.HandlerError
	if errors.As(err, &he) {
		return he.StatusCode
	}
	return 0
}

var tokRe = regexp.MustCompile(`var T="([A-Za-z0-9_.\-]+)"`)

func TestModuleFlow(t *testing.T) {
	c := newChallenge(t)
	const ip = "1.1.1.1"

	// Browser without cookie gets the page with a token.
	req := httptest.NewRequest("GET", "/shop?a=1", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	w, err, called := serve(c, ip, req)
	require.NoError(t, err)
	assert.False(t, called)
	assert.Equal(t, 200, w.Code)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	m := tokRe.FindStringSubmatch(w.Body.String())
	require.NotNil(t, m, w.Body.String())
	tok := m[1]
	assert.Contains(t, w.Body.String(), "/shop?a=1")

	// API client gets 403.
	req = httptest.NewRequest("GET", "/api", nil)
	req.Header.Set("Accept", "application/json")
	_, err, called = serve(c, ip, req)
	assert.Equal(t, 403, statusOf(err))
	assert.False(t, called)

	// POST with text/html also gets 403.
	req = httptest.NewRequest("POST", "/", nil)
	req.Header.Set("Accept", "text/html")
	_, err, _ = serve(c, ip, req)
	assert.Equal(t, 403, statusOf(err))

	// A nonce that does not satisfy the difficulty fails.
	bad := ""
	for i := 0; ; i++ {
		if n := "x" + strconv.Itoa(i); !validPoW(tok, n, 2) {
			bad = n
			break
		}
	}
	q := url.Values{"c": {tok}, "n": {bad}, "r": {"/shop?a=1"}}
	_, err, _ = serve(c, ip, httptest.NewRequest("GET", VerifyPath+"?"+q.Encode(), nil))
	assert.Equal(t, 403, statusOf(err))

	// A token issued to another IP fails even with a valid nonce.
	q = url.Values{"c": {tok}, "n": {solve(tok, 2)}}
	_, err, _ = serve(c, "9.9.9.9", httptest.NewRequest("GET", VerifyPath+"?"+q.Encode(), nil))
	assert.Equal(t, 403, statusOf(err))

	// Verify only accepts GET.
	_, err, _ = serve(c, ip, httptest.NewRequest("POST", VerifyPath, nil))
	assert.Equal(t, 405, statusOf(err))

	// Solved nonce gives 302 (unsafe return sanitised) and a clearance cookie.
	q = url.Values{"c": {tok}, "n": {solve(tok, 2)}, "r": {"//evil.com"}}
	w, err, called = serve(c, ip, httptest.NewRequest("GET", VerifyPath+"?"+q.Encode(), nil))
	require.NoError(t, err)
	assert.False(t, called)
	assert.Equal(t, 302, w.Code)
	assert.Equal(t, "/", w.Header().Get("Location"))
	var clr *http.Cookie
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "hi_clr" {
			clr = ck
		}
	}
	require.NotNil(t, clr)
	assert.True(t, clr.HttpOnly)
	assert.Equal(t, http.SameSiteLaxMode, clr.SameSite)
	assert.Equal(t, "/", clr.Path)
	assert.False(t, clr.Secure) // plain HTTP request

	// With the cookie the request passes through.
	req = httptest.NewRequest("GET", "/shop", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(clr)
	_, err, called = serve(c, ip, req)
	require.NoError(t, err)
	assert.True(t, called)

	// The cookie replayed from another IP is rejected.
	req = httptest.NewRequest("GET", "/shop", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(clr)
	_, err, called = serve(c, "9.9.9.9", req)
	assert.Equal(t, 403, statusOf(err))
	assert.False(t, called)
}
