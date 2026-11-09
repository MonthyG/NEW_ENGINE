// Package auth is the http.handlers.hi_auth middleware: a password gate
// (SafeLine's "Auth" challenge) in front of a site.
package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"hostinginside/waf/engine/events"
)

const (
	// LoginPath receives the login form.
	LoginPath = "/.hi-waf/auth"
	// LogoutPath clears the session cookie.
	LogoutPath = "/.hi-waf/logout"
	// CookieName is the session cookie.
	CookieName = "hi_auth"

	defaultTTL = 86400
	maxForm    = 8 << 10
)

//go:embed page.html
var pageSrc string

var pageTmpl = template.Must(template.New("auth").Parse(pageSrc))

// dummyHash is compared against when the username is unknown, so a login for
// a missing user costs as much as one for a real user.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("hi-waf-dummy-password"), bcrypt.DefaultCost)

func init() {
	caddy.RegisterModule(Auth{})
}

// User is one account allowed through the gate.
type User struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"` // bcrypt
}

// Auth is the http.handlers.hi_auth middleware.
type Auth struct {
	SiteID        string `json:"site_id"`
	Secret        string `json:"secret"` // std base64 of >= 32 bytes
	Users         []User `json:"users"`
	SessionTTLSec int    `json:"session_ttl_sec,omitempty"`
	Title         string `json:"title,omitempty"`

	key    []byte
	hashes map[string][]byte
	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hi_auth",
		New: func() caddy.Module { return new(Auth) },
	}
}

// Provision decodes the secret and indexes the users.
func (a *Auth) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	return a.setup()
}

func (a *Auth) setup() error {
	if a.SessionTTLSec == 0 {
		a.SessionTTLSec = defaultTTL
	}
	if a.Title == "" {
		a.Title = "Authentication required"
	}
	key, err := base64.StdEncoding.DecodeString(a.Secret)
	if err != nil {
		return fmt.Errorf("secret: %w", err)
	}
	a.key = key
	a.hashes = make(map[string][]byte, len(a.Users))
	for _, u := range a.Users {
		a.hashes[u.Username] = []byte(u.PasswordHash)
	}
	return nil
}

// Validate checks the config.
func (a *Auth) Validate() error {
	if a.SiteID == "" {
		return errors.New("site_id is required")
	}
	if len(a.key) < 32 {
		return errors.New("secret must decode to at least 32 bytes")
	}
	if len(a.Users) == 0 {
		return errors.New("at least one user is required")
	}
	for i, u := range a.Users {
		if u.Username == "" || strings.ContainsAny(u.Username, "|.") {
			return fmt.Errorf("users[%d]: invalid username", i)
		}
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return fmt.Errorf("users[%d]: password_hash is not a bcrypt hash", i)
		}
	}
	if a.SessionTTLSec < 1 {
		return errors.New("session_ttl_sec must be > 0")
	}
	return nil
}

func (a *Auth) mac(user, exp string) []byte {
	h := hmac.New(sha256.New, a.key)
	h.Write([]byte("auth|" + a.SiteID + "|" + user + "|" + exp + "|"))
	h.Write(a.hashes[user]) // a new password (new bcrypt hash) ends the user's old sessions
	return h.Sum(nil)
}

var b64 = base64.RawURLEncoding

// session returns "<b64 user>.<unix exp>.<b64 mac>".
func (a *Auth) session(user string, exp time.Time) string {
	e := strconv.FormatInt(exp.Unix(), 10)
	return b64.EncodeToString([]byte(user)) + "." + e + "." + b64.EncodeToString(a.mac(user, e))
}

// checkSession returns the user of a valid, unexpired session for a user that
// still exists.
func (a *Auth) checkSession(v string, now time.Time) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", false
	}
	u, err := b64.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	got, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(got, a.mac(string(u), parts[1])) {
		return "", false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || !now.Before(time.Unix(exp, 0)) {
		return "", false
	}
	if _, ok := a.hashes[string(u)]; !ok {
		return "", false
	}
	return string(u), true
}

// ServeHTTP lets requests with a valid session through and otherwise serves
// the login page (browsers) or 401.
func (a *Auth) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	now := time.Now()
	switch r.URL.Path {
	case LogoutPath:
		http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
		http.Redirect(w, r, "/", http.StatusFound)
		return nil
	case LoginPath:
		if r.Method == http.MethodPost {
			return a.login(w, r, now)
		}
	}
	if ck, err := r.Cookie(CookieName); err == nil {
		if _, ok := a.checkSession(ck.Value, now); ok {
			return next.ServeHTTP(w, r)
		}
	}
	events.Tag(r, events.ActionAuth, "auth_required")
	ret := r.URL.RequestURI()
	if r.URL.Path == LoginPath {
		ret = r.URL.Query().Get("r")
	}
	if wantsHTML(r) {
		return a.page(w, r, http.StatusUnauthorized, safeReturn(ret), "")
	}
	return caddyhttp.Error(http.StatusUnauthorized, errors.New("authentication required"))
}

func (a *Auth) login(w http.ResponseWriter, r *http.Request, now time.Time) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxForm)
	if err := r.ParseForm(); err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	user, pass := r.PostForm.Get("username"), r.PostForm.Get("password")
	ret := safeReturn(r.PostForm.Get("r"))
	hash, known := a.hashes[user]
	if !known {
		hash = dummyHash
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(pass)) != nil || !known {
		a.emit(r, events.TypeAuthFailed, user)
		events.Tag(r, events.ActionAuth, events.TypeAuthFailed)
		return a.page(w, r, http.StatusUnauthorized, ret, "Wrong username or password.")
	}
	exp := now.Add(time.Duration(a.SessionTTLSec) * time.Second)
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: a.session(user, exp), Path: "/", Expires: exp,
		MaxAge: a.SessionTTLSec, HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	a.emit(r, events.TypeAuthPassed, user)
	http.Redirect(w, r, ret, http.StatusSeeOther)
	return nil
}

func (a *Auth) page(w http.ResponseWriter, r *http.Request, status int, ret, msg string) error {
	var buf bytes.Buffer
	if err := pageTmpl.Execute(&buf, map[string]any{
		"Title": a.Title, "Action": LoginPath, "Return": ret, "Error": msg,
	}); err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(buf.Bytes())
	}
	return nil
}

func (a *Auth) emit(r *http.Request, typ, detail string) {
	if a.logger == nil {
		return
	}
	e := events.FromRequest(r, typ, a.SiteID)
	e.Msg = detail
	events.Emit(a.logger, e)
}

func wantsHTML(r *http.Request) bool {
	return (r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodPost) &&
		strings.Contains(r.Header.Get("Accept"), "text/html")
}

// safeReturn returns p if it is a same-site absolute path, otherwise "/".
func safeReturn(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.ContainsAny(p, "\\\r\n\t") ||
		strings.HasPrefix(p, LoginPath) {
		return "/"
	}
	return p
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Auth)(nil)
	_ caddy.Validator             = (*Auth)(nil)
	_ caddyhttp.MiddlewareHandler = (*Auth)(nil)
)
