package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

const (
	// SessionCookie is the console session cookie.
	SessionCookie = "hiwaf_session"
	// CSRFHeader must accompany every state-changing request made with a
	// session cookie; browsers can't send it cross-site without CORS.
	CSRFHeader = "X-Requested-With"
	csrfValue  = "hiwaf"

	sessionTTL     = 12 * time.Hour
	minPassword    = 8
	maxFailures    = 5  // per client address (IPv6: per /64)
	maxUserFails   = 50 // per account, from any number of addresses
	failureWindow  = 15 * time.Minute
	issuer         = "HostingInside WAF"
	defaultAdmin   = "admin"
	principalKey   = ctxKey("principal")
	tokenPrefix    = "hiw_"
	sessionIDBytes = 32
)

type ctxKey string

var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("hiwaf-no-such-user"), bcrypt.DefaultCost)

// principal is who is calling: a console user, or an API key/token. A
// principal with a Project acts only for that project (see tenant.go).
type principal struct {
	User    string // console username; empty for keys and tokens
	Session string // hash of the session ID, for session callers
	Project string // the project it is limited to; empty = the operator, unlimited
	Locked  bool   // the project comes from the token itself and can't be changed
}

func hashHex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func randomString(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails since Go 1.24
	return base64.RawURLEncoding.EncodeToString(b)
}

// publicRoutes need no authentication.
var publicRoutes = map[string]bool{
	"POST /api/v1/auth/login": true,
}

func (a *API) authenticate(r *http.Request) (principal, bool) {
	if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && tok != "" {
		sum := sha256.Sum256([]byte(tok))
		match := 0
		for _, k := range a.keys {
			match |= subtle.ConstantTimeCompare(sum[:], k[:])
		}
		if match == 1 {
			return principal{}, true
		}
		if strings.HasPrefix(tok, tokenPrefix) {
			if t, ok, err := a.st.TokenByHash(r.Context(), hex.EncodeToString(sum[:])); err == nil && ok {
				return principal{Project: t.Project, Locked: t.Project != ""}, true
			}
		}
		return principal{}, false
	}
	if ck, err := r.Cookie(SessionCookie); err == nil && ck.Value != "" {
		h := hashHex(ck.Value)
		if user, ok, err := a.st.SessionUser(r.Context(), h, time.Now()); err == nil && ok {
			return principal{User: user, Session: h}, true
		}
	}
	return principal{}, false
}

func (a *API) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if publicRoutes[r.Method+" "+r.URL.Path] {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := a.authenticate(r)
		if !ok {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, http.StatusUnauthorized, errBody{Error: "missing or invalid credentials"})
			return
		}
		if p.Session != "" && r.Method != http.MethodGet && r.Method != http.MethodHead &&
			r.Header.Get(CSRFHeader) != csrfValue {
			writeJSON(w, http.StatusForbidden, errBody{Error: "missing " + CSRFHeader + " header"})
			return
		}
		if h := r.Header.Get(ProjectHeader); h != "" {
			switch {
			case !site.ValidProject(h):
				writeJSON(w, http.StatusBadRequest, errBody{Error: ProjectHeader + " must be 1-64 letters, digits, - or _", Field: "project"})
				return
			case p.Locked && h != p.Project:
				writeJSON(w, http.StatusForbidden, errBody{Error: "this token belongs to another project"})
				return
			}
			p.Project = h
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}

func principalOf(r *http.Request) principal {
	p, _ := r.Context().Value(principalKey).(principal)
	return p
}

// --- admin bootstrap ---------------------------------------------------------

// EnsureAdmin creates the "admin" console user with a random password when no
// user exists, returning that password; it returns "" otherwise.
func EnsureAdmin(ctx context.Context, st *store.Store) (string, error) {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return "", err
	}
	return ResetAdmin(ctx, st)
}

// ResetAdmin sets a new random password for "admin" (creating it if needed),
// turns off its TOTP and ends its sessions. It returns the password.
func ResetAdmin(ctx context.Context, st *store.Store) (string, error) {
	pw := randomString(12)
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	u, err := st.GetUser(ctx, defaultAdmin)
	if err != nil && !errors.Is(err, store.ErrNoUser) {
		return "", err
	}
	u.Username, u.Hash, u.TOTPEnabled, u.TOTPSecret = defaultAdmin, string(h), false, ""
	if err := st.PutUser(ctx, u); err != nil {
		return "", err
	}
	return pw, st.DeleteUserSessions(ctx, defaultAdmin, "")
}

// SetAdminNote names the file that holds admin's first password, so the
// console can delete it once that password is changed.
func (a *API) SetAdminNote(path string) { a.note = path }

// CleanAdminNote deletes the first-password file when the password in it no
// longer signs in as admin (changed in the console or with -resetadmin), so
// a stale password doesn't sit on disk. It reports whether it deleted it.
func CleanAdminNote(ctx context.Context, st *store.Store, path string) (bool, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	var pw string
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "Password: "); ok {
			pw = strings.TrimSpace(v)
		}
	}
	u, err := st.GetUser(ctx, defaultAdmin)
	if err != nil && !errors.Is(err, store.ErrNoUser) {
		return false, err
	}
	if err == nil && pw != "" && bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(pw)) == nil {
		return false, nil
	}
	return true, os.Remove(path)
}

// --- login limiter -----------------------------------------------------------

// loginLimiter counts failed logins per client address and per account.
type loginLimiter struct {
	mu      sync.Mutex
	fail    map[string][]time.Time
	sweepAt int // map size that triggers dropping keys with no recent failures
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{fail: map[string][]time.Time{}, sweepAt: 1024}
}

func (l *loginLimiter) recent(key string, now time.Time) []time.Time {
	kept := l.fail[key][:0]
	for _, t := range l.fail[key] {
		if now.Sub(t) < failureWindow {
			kept = append(kept, t)
		}
	}
	if len(kept) == 0 {
		delete(l.fail, key)
		return nil
	}
	l.fail[key] = kept
	return kept
}

func (l *loginLimiter) blocked(key string, now time.Time, max int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.recent(key, now)) >= max
}

func (l *loginLimiter) failed(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fail[key] = append(l.recent(key, now), now)
	// Keys are only pruned when seen again, so one-off usernames would pile up
	// forever; sweep them, at most once per doubling to keep this amortised O(1).
	if len(l.fail) >= l.sweepAt {
		for k := range l.fail {
			l.recent(k, now)
		}
		l.sweepAt = max(1024, 2*len(l.fail))
	}
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fail, key)
}

func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// clientKey is the login limiter's key for the caller: its IPv4 address, or
// the /64 of its IPv6 address, since one IPv6 client typically holds a whole
// /64 and could otherwise use a fresh address for every guess.
func clientKey(r *http.Request) string {
	ip := net.ParseIP(remoteIP(r))
	if ip == nil || ip.To4() != nil {
		return remoteIP(r)
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// --- login / logout / me -----------------------------------------------------

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
	TOTP     string `json:"totp,omitempty"`
}

type meView struct {
	Username    string `json:"username"`
	TOTPEnabled bool   `json:"totp_enabled"`
	Kind        string `json:"kind"`              // user | token
	Project     string `json:"project,omitempty"` // set when the caller acts for one project
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	if len(req.Username) > 64 { // no real account is longer; keeps limiter keys small
		writeJSON(w, http.StatusUnauthorized, errBody{Error: "wrong username or password"})
		return
	}
	key, userKey, t := clientKey(r), "user:"+strings.ToLower(req.Username), time.Now()
	if a.limiter.blocked(key, t, maxFailures) || a.limiter.blocked(userKey, t, maxUserFails) {
		writeJSON(w, http.StatusTooManyRequests, errBody{Error: "too many failed logins; try again in 15 minutes"})
		return
	}
	// Count the attempt before checking it, so parallel requests can't all
	// pass the check above; a successful login clears the count.
	a.limiter.failed(key, t)
	a.limiter.failed(userKey, t)
	u, err := a.st.GetUser(r.Context(), req.Username)
	if err != nil && !errors.Is(err, store.ErrNoUser) {
		a.writeErr(w, err)
		return
	}
	hash := u.Hash
	if hash == "" {
		hash = string(dummyHash) // a missing user costs as much as a real one
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)) != nil || u.Username == "" {
		writeJSON(w, http.StatusUnauthorized, errBody{Error: "wrong username or password"})
		return
	}
	if u.TOTPEnabled {
		if req.TOTP == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "two-factor code required", "totp_required": true})
			return
		}
		if !validTOTP(u.TOTPSecret, req.TOTP, t) {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "wrong two-factor code", "totp_required": true})
			return
		}
	}
	a.limiter.reset(key)
	a.limiter.reset(userKey)
	sid := randomString(sessionIDBytes)
	exp := t.Add(sessionTTL)
	if err := a.st.CreateSession(r.Context(), hashHex(sid), u.Username, exp); err != nil {
		a.writeErr(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: sid, Path: "/", Expires: exp, MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
	writeJSON(w, http.StatusOK, meView{Username: u.Username, TOTPEnabled: u.TOTPEnabled, Kind: "user"})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if p := principalOf(r); p.Session != "" {
		_ = a.st.DeleteSession(r.Context(), p.Session)
	}
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	p := principalOf(r)
	if p.User == "" {
		writeJSON(w, http.StatusOK, meView{Username: "api", Kind: "token", Project: p.Project})
		return
	}
	u, err := a.st.GetUser(r.Context(), p.User)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, meView{Username: u.Username, TOTPEnabled: u.TOTPEnabled, Kind: "user", Project: p.Project})
}

// currentUser returns the calling console user, or a 403 for API keys.
func (a *API) currentUser(r *http.Request) (store.User, error) {
	p := principalOf(r)
	if p.User == "" {
		return store.User{}, &httpError{status: http.StatusForbidden, msg: "only console users can manage their account"}
	}
	return a.st.GetUser(r.Context(), p.User)
}

type passwordReq struct {
	Old string `json:"old_password"`
	New string `json:"new_password"`
}

func (a *API) changePassword(w http.ResponseWriter, r *http.Request) {
	var req passwordReq
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	u, err := a.currentUser(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(req.Old)) != nil {
		a.writeErr(w, badRequest("old_password", "is wrong"))
		return
	}
	if utf8.RuneCountInString(req.New) < minPassword || len(req.New) > 72 {
		a.writeErr(w, badRequest("new_password", fmt.Sprintf("must be %d-72 characters", minPassword)))
		return
	}
	h, err := bcrypt.GenerateFromPassword([]byte(req.New), bcrypt.DefaultCost)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	u.Hash = string(h)
	if err := a.st.PutUser(r.Context(), u); err != nil {
		a.writeErr(w, err)
		return
	}
	// Other sessions end; this one stays.
	if err := a.st.DeleteUserSessions(r.Context(), u.Username, principalOf(r).Session); err != nil {
		a.writeErr(w, err)
		return
	}
	if a.note != "" && u.Username == defaultAdmin {
		if _, err := CleanAdminNote(r.Context(), a.st, a.note); err != nil {
			a.log.Warn("could not delete the first-password file", "file", a.note, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- TOTP --------------------------------------------------------------------

type totpSetupView struct {
	Secret string `json:"secret"`
	URL    string `json:"otpauth_url"`
}

func (a *API) totpSetup(w http.ResponseWriter, r *http.Request) {
	u, err := a.currentUser(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if u.TOTPEnabled {
		a.writeErr(w, &httpError{status: http.StatusConflict, msg: "two-factor authentication is already on"})
		return
	}
	u.TOTPSecret = newTOTPSecret()
	if err := a.st.PutUser(r.Context(), u); err != nil {
		a.writeErr(w, err)
		return
	}
	label := url.PathEscape(issuer + ":" + u.Username)
	q := url.Values{"secret": {u.TOTPSecret}, "issuer": {issuer}}
	writeJSON(w, http.StatusOK, totpSetupView{Secret: u.TOTPSecret, URL: "otpauth://totp/" + label + "?" + q.Encode()})
}

type codeReq struct {
	Code     string `json:"code,omitempty"`
	Password string `json:"password,omitempty"`
}

func (a *API) totpEnable(w http.ResponseWriter, r *http.Request) {
	var req codeReq
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	u, err := a.currentUser(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if u.TOTPSecret == "" {
		a.writeErr(w, badRequest("", "call totp/setup first"))
		return
	}
	if !validTOTP(u.TOTPSecret, req.Code, time.Now()) {
		a.writeErr(w, badRequest("code", "is wrong"))
		return
	}
	u.TOTPEnabled = true
	if err := a.st.PutUser(r.Context(), u); err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) totpDisable(w http.ResponseWriter, r *http.Request) {
	var req codeReq
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	u, err := a.currentUser(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(req.Password)) != nil {
		a.writeErr(w, badRequest("password", "is wrong"))
		return
	}
	u.TOTPEnabled, u.TOTPSecret = false, ""
	if err := a.st.PutUser(r.Context(), u); err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- API tokens --------------------------------------------------------------

type tokenView struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Project  string     `json:"project,omitempty"` // the token acts only for this project
	Created  time.Time  `json:"created"`
	LastUsed *time.Time `json:"last_used,omitempty"`
	Expires  *time.Time `json:"expires,omitempty"` // absent = never
	Token    string     `json:"token,omitempty"`   // only in the create response
}

func (a *API) listTokens(w http.ResponseWriter, r *http.Request) {
	ts, err := a.st.ListTokens(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := make([]tokenView, 0, len(ts))
	for _, t := range ts {
		v := tokenView{ID: t.ID, Name: t.Name, Project: t.Project, Created: t.Created}
		if !t.LastUsed.IsZero() {
			lu := t.LastUsed
			v.LastUsed = &lu
		}
		if !t.Expires.IsZero() {
			e := t.Expires
			v.Expires = &e
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) createToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Project     string `json:"project"`      // empty = an operator token
		ExpiresDays int    `json:"expires_days"` // 0 = never
	}
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	if strings.TrimSpace(req.Name) == "" || utf8.RuneCountInString(req.Name) > 64 {
		a.writeErr(w, badRequest("name", "must be 1-64 characters"))
		return
	}
	if req.Project != "" && !site.ValidProject(req.Project) {
		a.writeErr(w, badRequest("project", "must be 1-64 letters, digits, - or _"))
		return
	}
	if req.ExpiresDays < 0 || req.ExpiresDays > 3650 {
		a.writeErr(w, badRequest("expires_days", "must be 0 (never) to 3650"))
		return
	}
	v := tokenView{ID: site.NewObjectID("t"), Name: req.Name, Project: req.Project, Created: now(),
		Token: tokenPrefix + randomString(24)}
	var exp time.Time
	if req.ExpiresDays > 0 {
		exp = v.Created.Add(time.Duration(req.ExpiresDays) * 24 * time.Hour)
		v.Expires = &exp
	}
	if err := a.st.CreateToken(r.Context(), v.ID, req.Name, req.Project, hashHex(v.Token), exp); err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, v)
}

func (a *API) deleteToken(w http.ResponseWriter, r *http.Request) {
	ok, err := a.st.DeleteToken(r.Context(), r.PathValue("id"))
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if !ok {
		a.writeErr(w, errNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
