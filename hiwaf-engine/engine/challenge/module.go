package challenge

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"hostinginside/waf/engine/clientip"
	"hostinginside/waf/engine/events"
)

const (
	// VerifyPath is where the challenge page sends the solved proof of work.
	VerifyPath = "/.hi-waf/verify"
	// CookieName is the clearance cookie set after a passed challenge.
	CookieName = "hi_clr"

	defaultDifficulty = 4
	defaultClearance  = 3600
)

//go:embed page.html
var pageSrc string

var pageTmpl = template.Must(template.New("page").Parse(pageSrc))

func init() {
	caddy.RegisterModule(Challenge{})
}

// Challenge is the http.handlers.hi_challenge middleware: a JS proof-of-work
// bot challenge. Clients without a valid clearance cookie get the challenge
// page (browsers) or a 403 (everything else).
type Challenge struct {
	SiteID          string `json:"site_id"`
	Secret          string `json:"secret"` // std base64 of >= 32 bytes
	Difficulty      int    `json:"difficulty,omitempty"`
	ClearanceTTLSec int    `json:"clearance_ttl_sec,omitempty"`

	key    []byte
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Challenge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hi_challenge",
		New: func() caddy.Module { return new(Challenge) },
	}
}

// Provision applies defaults and decodes the secret.
func (c *Challenge) Provision(ctx caddy.Context) error {
	c.logger = ctx.Logger()
	return c.setup()
}

func (c *Challenge) setup() error {
	if c.Difficulty == 0 {
		c.Difficulty = defaultDifficulty
	}
	if c.ClearanceTTLSec == 0 {
		c.ClearanceTTLSec = defaultClearance
	}
	key, err := base64.StdEncoding.DecodeString(c.Secret)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	c.key = key
	return nil
}

// Validate checks the config.
func (c *Challenge) Validate() error {
	if c.SiteID == "" {
		return errors.New("site_id is required")
	}
	if c.Difficulty < 1 || c.Difficulty > 6 {
		return errors.New("difficulty must be between 1 and 6")
	}
	if c.ClearanceTTLSec < 1 {
		return errors.New("clearance_ttl_sec must be > 0")
	}
	if len(c.key) < 32 {
		return errors.New("secret must decode to at least 32 bytes")
	}
	return nil
}

// ServeHTTP verifies solved challenges, honours clearance cookies, and
// otherwise serves the challenge page or a 403.
func (c *Challenge) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := clientip.Get(r)
	now := time.Now()

	if r.URL.Path == VerifyPath {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			return caddyhttp.Error(http.StatusMethodNotAllowed, errors.New("method not allowed"))
		}
		q := r.URL.Query()
		tok, nonce := q.Get("c"), q.Get("n")
		if err := checkToken(c.key, tok, c.SiteID, ip, now); err != nil {
			return c.fail(r, err.Error())
		}
		if !validPoW(tok, nonce, c.Difficulty) {
			return c.fail(r, "invalid proof of work")
		}
		exp := now.Add(time.Duration(c.ClearanceTTLSec) * time.Second)
		http.SetCookie(w, &http.Cookie{
			Name:     CookieName,
			Value:    makeClearance(c.key, c.SiteID, ip, exp),
			Path:     "/",
			Expires:  exp,
			MaxAge:   c.ClearanceTTLSec,
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
		})
		c.emit(r, events.TypeChallengePassed, "")
		http.Redirect(w, r, safeReturn(q.Get("r")), http.StatusFound)
		return nil
	}

	if ck, err := r.Cookie(CookieName); err == nil && checkClearance(c.key, ck.Value, c.SiteID, ip, now) {
		return next.ServeHTTP(w, r)
	}

	if (r.Method == http.MethodGet || r.Method == http.MethodHead) &&
		strings.Contains(r.Header.Get("Accept"), "text/html") {
		var buf bytes.Buffer
		err := pageTmpl.Execute(&buf, map[string]any{
			"Token":      issueToken(c.key, c.SiteID, ip, now),
			"Difficulty": c.Difficulty,
			"Return":     safeReturn(r.URL.RequestURI()),
		})
		if err != nil {
			return caddyhttp.Error(http.StatusInternalServerError, err)
		}
		events.Tag(r, events.ActionChallenge, "challenge_issued")
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(buf.Bytes())
		}
		return nil
	}

	events.Tag(r, events.ActionChallenge, "challenge_required")
	return caddyhttp.Error(http.StatusForbidden, errors.New("challenge required"))
}

func (c *Challenge) fail(r *http.Request, why string) error {
	c.emit(r, events.TypeChallengeFailed, why)
	events.Tag(r, events.ActionChallenge, events.TypeChallengeFailed)
	return caddyhttp.Error(http.StatusForbidden, errors.New("challenge failed"))
}

func (c *Challenge) emit(r *http.Request, typ, detail string) {
	if c.logger == nil {
		return
	}
	e := events.FromRequest(r, typ, c.SiteID)
	e.Msg = detail
	events.Emit(c.logger, e)
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Challenge)(nil)
	_ caddy.Validator             = (*Challenge)(nil)
	_ caddyhttp.MiddlewareHandler = (*Challenge)(nil)
)
