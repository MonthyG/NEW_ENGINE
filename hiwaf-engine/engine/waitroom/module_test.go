package waitroom

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdmitFIFO(t *testing.T) {
	r := newRoom()
	now := time.Now()
	ttl := time.Minute
	assert.Equal(t, 0, r.admit("a", "", false, 2, ttl, now))
	assert.Equal(t, 0, r.admit("b", "", false, 2, ttl, now))
	assert.Equal(t, 1, r.admit("c", "", false, 2, ttl, now))
	assert.Equal(t, 2, r.admit("d", "", false, 2, ttl, now))
	assert.Equal(t, 0, r.admit("a", "", false, 2, ttl, now), "active visitor keeps its slot")

	// a and b go idle; c is admitted first, then d, and a returning a queues.
	later := now.Add(ttl + time.Second)
	r.polled["c"], r.polled["d"] = later, later
	assert.Equal(t, 0, r.admit("c", "", false, 2, ttl, later))
	assert.Equal(t, 0, r.admit("d", "", false, 2, ttl, later))
	assert.Equal(t, 1, r.admit("a", "", false, 2, ttl, later))
}

func TestStaleQueueEntriesDropped(t *testing.T) {
	r := newRoom()
	now := time.Now()
	r.admit("a", "", false, 1, time.Hour, now)
	assert.Equal(t, 1, r.admit("b", "", false, 1, time.Hour, now))
	assert.Equal(t, 2, r.admit("c", "", false, 1, time.Hour, now))
	// b stops polling; c moves up.
	assert.Equal(t, 1, r.admit("c", "", false, 1, time.Hour, now.Add(queueStaleness+time.Second)))
}

func TestServeHTTPQueuesWithPage(t *testing.T) {
	wr := &WaitRoom{SiteID: "s_waittest00001", Secret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=", MaxActive: 1}
	require.NoError(t, wr.setup())
	require.NoError(t, wr.Validate())
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) error { return nil })
	do := func(ck *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Accept", "text/html")
		if ck != nil {
			req.AddCookie(ck)
		}
		req = req.WithContext(context.WithValue(req.Context(), caddyhttp.VarsCtxKey, map[string]any{}))
		w := httptest.NewRecorder()
		require.NoError(t, wr.ServeHTTP(w, req, next))
		return w
	}
	first := do(nil)
	assert.Equal(t, http.StatusOK, first.Code)
	ck := first.Result().Cookies()[0]
	assert.Equal(t, http.StatusOK, do(ck).Code, "same visitor stays admitted")
	second := do(nil)
	assert.Equal(t, http.StatusServiceUnavailable, second.Code)
	assert.Contains(t, second.Body.String(), ">1<")
}

func TestFreshVisitorsNeverQueue(t *testing.T) {
	r := newRoom()
	now := time.Now()
	assert.Equal(t, 0, r.admit("a", "1.1.1.1", true, 1, time.Minute, now))
	for _, id := range []string{"b", "c", "d"} { // a cookie-dropping client
		assert.Equal(t, 1, r.admit(id, "2.2.2.2", true, 1, time.Minute, now))
	}
	assert.Empty(t, r.queue, "visitors without a cookie are not queued")
	assert.Equal(t, 1, r.admit("b", "2.2.2.2", false, 1, time.Minute, now), "back with the cookie: queued")
	assert.Len(t, r.queue, 1)
}

func TestOneClientCannotFillTheRoom(t *testing.T) {
	r := newRoom()
	now := time.Now()
	for i := 0; i < maxPerClient; i++ {
		assert.Equal(t, 0, r.admit(fmt.Sprint("x", i), "6.6.6.6", true, 1000, time.Minute, now))
	}
	assert.NotZero(t, r.admit("x-more", "6.6.6.6", true, 1000, time.Minute, now), "over its share: no slot")
	assert.Equal(t, 0, r.admit("y", "7.7.7.7", true, 1000, time.Minute, now), "other clients still get in")
	// slots freed by idle visitors are no longer counted
	later := now.Add(2 * time.Minute)
	assert.Equal(t, 0, r.admit("x-later", "6.6.6.6", true, 1000, time.Minute, later))
	assert.Len(t, r.client, 1)
}
