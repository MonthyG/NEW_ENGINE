// Package caddyclient talks to Caddy's admin API: config loads and the
// hi_bans admin module.
package caddyclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ErrUnreachable means the Caddy admin endpoint could not be contacted.
var ErrUnreachable = errors.New("caddy admin unreachable")

// LoadError is a non-2xx answer from the admin API; Body is the raw response text.
type LoadError struct {
	Status int
	Body   string
}

func (e *LoadError) Error() string {
	return fmt.Sprintf("caddy admin returned %d: %s", e.Status, e.Body)
}

// Client is a Caddy admin API client.
type Client struct {
	// BaseURL is http://localhost:2019 or a unix socket, unix:///data/caddy-admin.sock.
	BaseURL string
	// Bootstrap is the TCP address Load falls back to while the socket does
	// not exist: a fresh engine listens on Caddy's default until the first
	// load (whose config names the socket) moves its admin API there.
	Bootstrap string
	HTTP      *http.Client // nil: a plain client; do sets the timeouts

	once sync.Once
	unix *http.Client
}

// Timeouts: a load compiles every site's WAF rules, which takes longer the
// more sites there are, so it gets far more time than the small calls.
const (
	callTimeout = 30 * time.Second
	loadTimeout = 5 * time.Minute
)

// Ban is one banned IP.
type Ban struct {
	IP    string    `json:"ip"`
	Until time.Time `json:"until"`
}

// client returns the HTTP client and URL prefix for base.
func (c *Client) client(base string) (*http.Client, string) {
	sock, ok := strings.CutPrefix(base, "unix://")
	if !ok {
		if c.HTTP != nil {
			return c.HTTP, strings.TrimRight(base, "/")
		}
		return http.DefaultClient, strings.TrimRight(base, "/")
	}
	c.once.Do(func() {
		c.unix = &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}}}
	})
	// Caddy does not check the Host of requests on a unix socket; any will do.
	return c.unix, "http://127.0.0.1"
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body []byte) (int, []byte, error) {
	timeout := callTimeout
	if path == "/load" {
		timeout = loadTimeout
	}
	status, b, err := c.doAt(ctx, c.BaseURL, timeout, method, path, q, body)
	// No socket (fresh engine) or a stale one (engine restarted without its
	// saved config): the engine is on Caddy's default TCP address.
	if errors.Is(err, ErrUnreachable) && path == "/load" && c.Bootstrap != "" && strings.HasPrefix(c.BaseURL, "unix://") {
		return c.doAt(ctx, c.Bootstrap, timeout, method, path, q, body)
	}
	return status, b, err
}

func (c *Client) doAt(parent context.Context, base string, timeout time.Duration, method, path string, q url.Values, body []byte) (int, []byte, error) {
	h, prefix := c.client(base)
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	u := prefix + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := h.Do(req)
	if err != nil {
		if parent.Err() != nil { // the caller gave up; our own timeout is "unreachable"
			return 0, nil, parent.Err()
		}
		return 0, nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %v", ErrUnreachable, err)
	}
	return resp.StatusCode, b, nil
}

// Load replaces Caddy's running config with cfg (POST /load).
func (c *Client) Load(ctx context.Context, cfg any) error {
	body, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	status, resp, err := c.do(ctx, http.MethodPost, "/load", nil, body)
	if err != nil {
		return err
	}
	if status < 200 || status > 299 {
		return &LoadError{Status: status, Body: string(resp)}
	}
	return nil
}

// Bans lists active bans per site; an empty siteID lists all sites.
func (c *Client) Bans(ctx context.Context, siteID string) (map[string][]Ban, error) {
	q := url.Values{}
	if siteID != "" {
		q.Set("site", siteID)
	}
	status, resp, err := c.do(ctx, http.MethodGet, "/hi/bans", q, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &LoadError{Status: status, Body: string(resp)}
	}
	out := map[string][]Ban{}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decode bans: %w", err)
	}
	return out, nil
}

// Unban lifts a ban; it reports false if the IP was not banned.
func (c *Client) Unban(ctx context.Context, siteID, ip string) (bool, error) {
	q := url.Values{}
	q.Set("site", siteID)
	q.Set("ip", ip)
	status, resp, err := c.do(ctx, http.MethodDelete, "/hi/bans", q, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusNoContent, http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, &LoadError{Status: status, Body: string(resp)}
}

// WaitRoom is one site's waiting-room occupancy.
type WaitRoom struct {
	Active  int `json:"active"`
	Waiting int `json:"waiting"`
}

// WaitRooms returns waiting-room occupancy per site. It doubles as the
// engine health check.
func (c *Client) WaitRooms(ctx context.Context) (map[string]WaitRoom, error) {
	status, resp, err := c.do(ctx, http.MethodGet, "/hi/waitroom", nil, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, &LoadError{Status: status, Body: string(resp)}
	}
	out := map[string]WaitRoom{}
	if err := json.Unmarshal(resp, &out); err != nil {
		return nil, fmt.Errorf("decode waitroom: %w", err)
	}
	return out, nil
}
