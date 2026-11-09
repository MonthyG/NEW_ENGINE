// Package alert tells the operator when something needs them: it watches the
// engine and posts to a webhook when it goes down or comes back, and pings a
// heartbeat URL while all is well, so an outside monitor notices when this
// host or the manager itself dies (which no alert from here can report).
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"hostinginside/waf/manager/store"
)

// Setting keys.
const (
	WebhookKey   = "alert_webhook"
	HeartbeatKey = "alert_heartbeat"
)

// ValidURL checks a webhook or heartbeat URL; empty means off.
func ValidURL(s string) error {
	if s == "" {
		return nil
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("must be an http:// or https:// URL")
	}
	return nil
}

// Notifier sends alerts to the configured webhook.
type Notifier struct {
	Store  *store.Store
	Host   string // names this edge in messages
	Log    *slog.Logger
	Client *http.Client // nil: 10 s timeout
}

func (n *Notifier) client() *http.Client {
	if n.Client != nil {
		return n.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Message is the webhook body. "text" is what Slack and most chat webhooks
// show, "content" is Discord's; the rest is for scripts.
type Message struct {
	Text    string    `json:"text"`
	Content string    `json:"content"`
	Event   string    `json:"event"`
	Host    string    `json:"host"`
	At      time.Time `json:"at"`
}

// Send posts an alert. It returns nil without sending when no webhook is set.
func (n *Notifier) Send(ctx context.Context, event, text string) error {
	hook, _, err := n.Store.Setting(ctx, WebhookKey)
	if err != nil || hook == "" {
		return err
	}
	text = "HostingInside WAF on " + n.Host + ": " + text
	body, _ := json.Marshal(Message{Text: text, Content: text, Event: event, Host: n.Host, At: time.Now().UTC()})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, hook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := n.client().Do(req)
	if err != nil {
		return fmt.Errorf("webhook: %w", err)
	}
	res.Body.Close()
	if res.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %s", res.Status)
	}
	return nil
}

// Notify sends an alert in the background and only logs failures; for
// callers that must not wait on a slow webhook.
func (n *Notifier) Notify(event, text string) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := n.Send(ctx, event, text); err != nil && n.Log != nil {
			n.Log.Warn("alert not sent", "event", event, "err", err)
		}
	}()
}

// Watcher probes the engine every Every and alerts after Fails probes in a
// row fail, and again when it answers once more. The zero Every and Fails
// mean 30 s and 2.
type Watcher struct {
	Probe    func(ctx context.Context) error
	Notifier *Notifier
	Every    time.Duration
	Fails    int

	mu        sync.Mutex
	downSince time.Time // zero while the engine is up (or not yet declared down)
}

// DownSince returns when the engine was declared down, or the zero time.
func (w *Watcher) DownSince() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.downSince
}

// Run watches until ctx ends.
func (w *Watcher) Run(ctx context.Context) {
	every, fails := w.Every, w.Fails
	if every <= 0 {
		every = 30 * time.Second
	}
	if fails <= 0 {
		fails = 2
	}
	t := time.NewTicker(every)
	defer t.Stop()
	failed := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := w.Probe(pctx)
		cancel()
		if ctx.Err() != nil {
			return
		}
		w.step(ctx, err, &failed, fails, every)
	}
}

// step records one probe result and sends what it calls for.
func (w *Watcher) step(ctx context.Context, err error, failed *int, fails int, every time.Duration) {
	w.mu.Lock()
	down := !w.downSince.IsZero()
	w.mu.Unlock()
	if err != nil {
		*failed++
		if !down && *failed == fails {
			since := time.Now().Add(-time.Duration(fails-1) * every)
			w.mu.Lock()
			w.downSince = since
			w.mu.Unlock()
			w.Notifier.Notify("engine_down", fmt.Sprintf("the engine is not answering (%v). Sites may be offline.", err))
		}
		return
	}
	*failed = 0
	if down {
		w.mu.Lock()
		since := w.downSince
		w.downSince = time.Time{}
		w.mu.Unlock()
		w.Notifier.Notify("engine_up", fmt.Sprintf("the engine is answering again after %s.", time.Since(since).Round(time.Second)))
	}
	w.heartbeat(ctx)
}

// heartbeat pings the heartbeat URL, if one is set.
func (w *Watcher) heartbeat(ctx context.Context) {
	n := w.Notifier
	u, _, err := n.Store.Setting(ctx, HeartbeatKey)
	if err != nil || u == "" {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return
	}
	res, err := n.client().Do(req)
	if err != nil {
		if n.Log != nil {
			n.Log.Warn("heartbeat failed", "err", err)
		}
		return
	}
	res.Body.Close()
}
