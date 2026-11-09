package alert

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"hostinginside/waf/manager/store"
)

// hook records webhook posts and heartbeat pings.
type hook struct {
	mu     sync.Mutex
	events []string
	beats  int
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Method == http.MethodGet {
		h.beats++
		return
	}
	var m Message
	_ = json.NewDecoder(r.Body).Decode(&m)
	h.events = append(h.events, m.Event)
}

func (h *hook) seen() ([]string, int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.events...), h.beats
}

func TestWatcherAlertsOnceThenRecovers(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "waf.db"))
	require.NoError(t, err)
	defer st.Close()
	h := &hook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	require.NoError(t, st.SetSetting(ctx, WebhookKey, srv.URL+"/hook"))
	require.NoError(t, st.SetSetting(ctx, HeartbeatKey, srv.URL+"/beat"))

	w := &Watcher{Notifier: &Notifier{Store: st, Host: "edge"}}
	failed, down := 0, errors.New("connection refused")
	w.step(ctx, nil, &failed, 2, time.Second) // healthy: heartbeat
	w.step(ctx, down, &failed, 2, time.Second)
	assert.True(t, w.DownSince().IsZero(), "one failed probe is not an outage")
	w.step(ctx, down, &failed, 2, time.Second)
	w.step(ctx, down, &failed, 2, time.Second) // still down: no second alert
	assert.False(t, w.DownSince().IsZero())
	w.step(ctx, nil, &failed, 2, time.Second)
	assert.True(t, w.DownSince().IsZero())

	assert.Eventually(t, func() bool { ev, _ := h.seen(); return len(ev) == 2 }, 5*time.Second, 20*time.Millisecond)
	ev, beats := h.seen()
	assert.ElementsMatch(t, []string{"engine_down", "engine_up"}, ev)
	assert.Equal(t, 2, beats, "heartbeats only while healthy")
}

func TestSendWithoutWebhookIsQuiet(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "waf.db"))
	require.NoError(t, err)
	defer st.Close()
	assert.NoError(t, (&Notifier{Store: st}).Send(context.Background(), "test", "x"))
}

func TestValidURL(t *testing.T) {
	assert.NoError(t, ValidURL(""))
	assert.NoError(t, ValidURL("https://hc-ping.com/abc"))
	for _, u := range []string{"file:///etc/passwd", "gopher://x", "https://", "not a url"} {
		assert.Error(t, ValidURL(u), u)
	}
}
