package ratelimit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func provision(t *testing.T, rl *RateLimit) *RateLimit {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	t.Cleanup(cancel)
	require.NoError(t, rl.Provision(ctx))
	require.NoError(t, rl.Validate())
	t.Cleanup(func() { _ = rl.Cleanup() })
	return rl
}

func reqFrom(ip string) *http.Request {
	r := httptest.NewRequest("GET", "/x", nil)
	r.RemoteAddr = ip + ":4321"
	return r
}

func wafErr(ruleID int) error {
	return caddyhttp.HandlerError{StatusCode: 403, ID: "tx1", Err: fmt.Errorf("interruption triggered by rule %d (%s)", ruleID, "deny")}
}

func status429(t *testing.T, err error) {
	t.Helper()
	var he caddyhttp.HandlerError
	require.True(t, errors.As(err, &he), "want HandlerError, got %v", err)
	assert.Equal(t, http.StatusTooManyRequests, he.StatusCode)
}

func TestIsWAFInterruptionPinsCorazaFormat(t *testing.T) {
	err := caddyhttp.HandlerError{StatusCode: 403, Err: fmt.Errorf("interruption triggered by rule %d (%s)", 949110, "deny")}
	id, ok := isWAFInterruption(err)
	assert.True(t, ok)
	assert.Equal(t, "949110", id)
	_, ok = isWAFInterruption(caddyhttp.Error(502, errors.New("dial tcp: refused")))
	assert.False(t, ok)
	_, ok = isWAFInterruption(nil)
	assert.False(t, ok)
	_, ok = isWAFInterruption(caddyhttp.Error(500, errors.New("interruption triggered elsewhere")))
	assert.False(t, ok)
}

// coraza-caddy v2.6.2 (latest release) returns a bare error without the rule ID.
func TestIsWAFInterruptionReleasedFormat(t *testing.T) {
	err := caddyhttp.HandlerError{StatusCode: 403, Err: errors.New("interruption triggered")}
	id, ok := isWAFInterruption(err)
	assert.True(t, ok)
	assert.Equal(t, "", id)
}

func TestAccessLimit429WithRetryAfter(t *testing.T) {
	rl := provision(t, &RateLimit{SiteID: "s_00000000ac01", Access: &Limit{Requests: 2, WindowSec: 10, BanSec: 60}})
	calls := 0
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { calls++; return nil })

	for i := 0; i < 2; i++ {
		require.NoError(t, rl.ServeHTTP(httptest.NewRecorder(), reqFrom("1.1.1.1"), next))
	}
	assert.Equal(t, 2, calls)

	w := httptest.NewRecorder()
	status429(t, rl.ServeHTTP(w, reqFrom("1.1.1.1"), next))
	assert.Equal(t, "60", w.Header().Get("Retry-After"))
	assert.Equal(t, 2, calls)

	// Still banned on the next request; another IP is unaffected.
	w = httptest.NewRecorder()
	status429(t, rl.ServeHTTP(w, reqFrom("1.1.1.1"), next))
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	require.NoError(t, rl.ServeHTTP(httptest.NewRecorder(), reqFrom("2.2.2.2"), next))
	assert.Equal(t, 3, calls)
}

func TestAttackCountsOnlyWAFErrors(t *testing.T) {
	rl := provision(t, &RateLimit{SiteID: "s_00000000at01", Attack: &Limit{Requests: 1, WindowSec: 60, BanSec: 600}})

	// Upstream errors are not attacks.
	upstream := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return caddyhttp.Error(502, errors.New("dial tcp: refused"))
	})
	for i := 0; i < 3; i++ {
		err := rl.ServeHTTP(httptest.NewRecorder(), reqFrom("3.3.3.3"), upstream)
		_, isWAF := isWAFInterruption(err)
		assert.False(t, isWAF)
		var he caddyhttp.HandlerError
		require.True(t, errors.As(err, &he))
		assert.Equal(t, 502, he.StatusCode)
	}

	calls := 0
	blocked := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { calls++; return wafErr(942100) })
	for i := 0; i < 2; i++ {
		err := rl.ServeHTTP(httptest.NewRecorder(), reqFrom("4.4.4.4"), blocked)
		_, isWAF := isWAFInterruption(err)
		assert.True(t, isWAF, "next's error is returned unchanged")
	}
	// The 2nd block banned the IP: the 3rd request never reaches next.
	status429(t, rl.ServeHTTP(httptest.NewRecorder(), reqFrom("4.4.4.4"), blocked))
	assert.Equal(t, 2, calls)
}

func TestErrorCountsUpstream404NotWAF403(t *testing.T) {
	lim := &Limit{Requests: 1, WindowSec: 60, BanSec: 60}
	notFound := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusNotFound)
		return nil
	})
	rl := provision(t, &RateLimit{SiteID: "s_00000000e401", Error: lim})
	for i := 0; i < 2; i++ {
		require.NoError(t, rl.ServeHTTP(httptest.NewRecorder(), reqFrom("5.5.5.5"), notFound))
	}
	status429(t, rl.ServeHTTP(httptest.NewRecorder(), reqFrom("5.5.5.5"), notFound))

	waf := provision(t, &RateLimit{SiteID: "s_00000000e402", Error: lim})
	calls := 0
	blocked := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { calls++; return wafErr(949110) })
	for i := 0; i < 3; i++ {
		err := waf.ServeHTTP(httptest.NewRecorder(), reqFrom("5.5.5.5"), blocked)
		_, isWAF := isWAFInterruption(err)
		assert.True(t, isWAF)
	}
	assert.Equal(t, 3, calls, "WAF 403s must not count toward the error limit")
}

func TestTxHeaderOverwritten(t *testing.T) {
	rl := provision(t, &RateLimit{SiteID: "s_aaaaaaaaaaaa"})
	var got string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		got = r.Header.Get(TxHeader)
		return nil
	})
	r := reqFrom("6.6.6.6")
	r.Header.Set(TxHeader, "evil")
	require.NoError(t, rl.ServeHTTP(httptest.NewRecorder(), r, next))
	assert.Regexp(t, regexp.MustCompile(`^s_aaaaaaaaaaaa-[0-9a-f]{16}$`), got)
}

func TestPoolStateSurvivesReload(t *testing.T) {
	const id = "s_00000000p001"
	lim := Limit{Requests: 1, WindowSec: 60, BanSec: 60}
	now := time.Now()

	st, err := acquire(id)
	require.NoError(t, err)
	st.Record(KindAttack, "7.7.7.7", lim, now)
	_, newly := st.Record(KindAttack, "7.7.7.7", lim, now)
	require.True(t, newly)

	st2, err := acquire(id) // new config provisions first...
	require.NoError(t, err)
	assert.Same(t, st, st2)
	require.NoError(t, release(id)) // ...then the old config cleans up

	got, ok := lookup(id)
	require.True(t, ok)
	_, banned := got.BannedUntil("7.7.7.7", now)
	assert.True(t, banned)

	require.NoError(t, release(id))
	_, ok = lookup(id)
	assert.False(t, ok)
}

func TestNoLimitsStillEmitsWAFBlock(t *testing.T) {
	rl := provision(t, &RateLimit{SiteID: "s_00000000n001"})
	core, logs := observer.New(zap.InfoLevel)
	rl.logger = zap.New(core)

	want := wafErr(949110)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return want })
	err := rl.ServeHTTP(httptest.NewRecorder(), reqFrom("8.8.8.8"), next)
	assert.Equal(t, want, err)

	entries := logs.FilterMessage("hi_event").All()
	require.Len(t, entries, 1)
	m := entries[0].ContextMap()
	assert.Equal(t, "waf_block", m["event"])
	assert.Equal(t, "949110", m["rule_id"])
	assert.Equal(t, "s_00000000n001", m["site_id"])
	assert.Equal(t, "8.8.8.8", m["client_ip"])
}

func TestBanEventEmittedOnceOnNewBan(t *testing.T) {
	rl := provision(t, &RateLimit{SiteID: "s_00000000b001", Access: &Limit{Requests: 1, WindowSec: 60, BanSec: 60}})
	core, logs := observer.New(zap.InfoLevel)
	rl.logger = zap.New(core)
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })
	for i := 0; i < 4; i++ {
		_ = rl.ServeHTTP(httptest.NewRecorder(), reqFrom("9.9.9.9"), next)
	}
	entries := logs.FilterMessage("hi_event").All()
	require.Len(t, entries, 1, "only the new ban is logged, not later 429s")
	m := entries[0].ContextMap()
	assert.Equal(t, "rate_limit_ban", m["event"])
	assert.Equal(t, "access", m["detail"])
	assert.NotEmpty(t, m["until"])
}

func TestValidate(t *testing.T) {
	assert.Error(t, (&RateLimit{}).Validate())
	assert.NoError(t, (&RateLimit{SiteID: "s_aaaaaaaaaaaa"}).Validate())
	assert.Error(t, (&RateLimit{SiteID: "s_aaaaaaaaaaaa", Error: &Limit{Requests: 1, WindowSec: 60}}).Validate())
	assert.NoError(t, (&RateLimit{SiteID: "s_aaaaaaaaaaaa", Attack: &Limit{10, 60, 1800}, Error: &Limit{50, 60, 600}}).Validate())
}

func TestBanAdminGetAndDelete(t *testing.T) {
	const id = "s_00000000ad01"
	st, err := acquire(id)
	require.NoError(t, err)
	t.Cleanup(func() { _ = release(id) })
	lim := Limit{Requests: 1, WindowSec: 60, BanSec: 600}
	now := time.Now()
	for _, ip := range []string{"10.0.0.2", "10.0.0.1"} {
		st.Record(KindAttack, ip, lim, now)
		st.Record(KindAttack, ip, lim, now)
	}

	h := BanAdmin{}.Routes()[0].Handler
	assert.Equal(t, "/hi/bans", BanAdmin{}.Routes()[0].Pattern)

	get := func(target string) map[string][]banEntry {
		w := httptest.NewRecorder()
		require.NoError(t, h.ServeHTTP(w, httptest.NewRequest("GET", target, nil)))
		assert.Equal(t, http.StatusOK, w.Code)
		var out map[string][]banEntry
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
		return out
	}

	one := get("/hi/bans?site=" + id)
	require.Len(t, one, 1)
	require.Len(t, one[id], 2)
	assert.Equal(t, "10.0.0.1", one[id][0].IP)
	until, err := time.Parse(time.RFC3339, one[id][0].Until)
	require.NoError(t, err)
	assert.WithinDuration(t, now.Add(600*time.Second), until, 2*time.Second)

	all := get("/hi/bans")
	assert.Len(t, all[id], 2)

	assert.Empty(t, get("/hi/bans?site=s_000000000000"))

	w := httptest.NewRecorder()
	require.NoError(t, h.ServeHTTP(w, httptest.NewRequest("DELETE", "/hi/bans?site="+id+"&ip=10.0.0.1", nil)))
	assert.Equal(t, http.StatusNoContent, w.Code)
	_, banned := st.BannedUntil("10.0.0.1", time.Now())
	assert.False(t, banned)

	var apiErr caddy.APIError
	err = h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("DELETE", "/hi/bans?site="+id+"&ip=10.0.0.1", nil))
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusNotFound, apiErr.HTTPStatus)

	err = h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("DELETE", "/hi/bans?site="+id, nil))
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusBadRequest, apiErr.HTTPStatus)
}
