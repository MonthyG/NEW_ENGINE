// Package api is the manager's REST API (spec §7): it validates site
// documents, stores them, compiles every site to one Caddy config and pushes
// it, rolling the database back when Caddy refuses or can't be reached. It
// also serves the console's endpoints: login, statistics, logs and the
// global objects (certificates, IP groups, custom rules).
package api

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/caddyclient"
	"hostinginside/waf/manager/compile"
	"hostinginside/waf/manager/crsplugins"
	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

const maxBody = 1 << 20

// Version is reported by GET /api/v1/system.
var Version = "1.0.0"

// Ruleset names the OWASP Core Rule Set built into the engine; a test keeps it
// in step with go.mod's coraza-coreruleset version. Newer releases can be
// installed beside it and switched to without a restart (see ops.go).
const Ruleset = "CRS 4.25.0"

// Loader pushes configs to the engine and manages its bans.
// *caddyclient.Client implements it.
type Loader interface {
	Load(ctx context.Context, cfg any) error
	Bans(ctx context.Context, siteID string) (map[string][]caddyclient.Ban, error)
	Unban(ctx context.Context, siteID, ip string) (bool, error)
	WaitRooms(ctx context.Context) (map[string]caddyclient.WaitRoom, error)
}

// API serves the management endpoints.
type API struct {
	st      *store.Store
	cl      Loader
	opt     compile.Options
	keys    [][32]byte // SHA-256 of each API key, so comparisons are fixed-length
	log     *slog.Logger
	limiter *loginLimiter
	started time.Time
	ops     Ops
	note    string // initial-admin.txt, removed once admin's password changes

	resyncing   atomic.Bool   // a resync after an unanswered load is running
	resyncRetry time.Duration // pause between resync attempts while the engine is unreachable
	lookupTXT   TXTLookup     // domain ownership check for project callers; nil: off
}

// New returns an API. Empty keys are ignored.
func New(st *store.Store, cl Loader, opt compile.Options, apiKeys []string) *API {
	a := &API{st: st, cl: cl, opt: opt, log: slog.Default(), limiter: newLoginLimiter(), started: time.Now(),
		resyncRetry: 30 * time.Second}
	for _, k := range apiKeys {
		if k != "" {
			a.keys = append(a.keys, sha256.Sum256([]byte(k)))
		}
	}
	return a
}

// Handler returns the HTTP handler for /api/v1. Every route except login
// requires an API key, an API token or a console session.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	handle := func(pattern string, s scope, h http.HandlerFunc) { mux.HandleFunc(pattern, a.gate(s, h)) }
	// Sites.
	handle("POST /api/v1/sites", anyCaller, a.createSite)
	handle("GET /api/v1/sites", anyCaller, a.listSites)
	handle("GET /api/v1/domain-check", anyCaller, a.domainCheck)
	handle("GET /api/v1/sites/{id}", siteInPath, a.getSite)
	handle("PUT /api/v1/sites/{id}", siteInPath, a.putSite)
	handle("PATCH /api/v1/sites/{id}", siteInPath, a.patchSite)
	handle("DELETE /api/v1/sites/{id}", siteInPath, a.deleteSite)
	handle("POST /api/v1/sites/{id}/exclusions", siteInPath, a.addExclusion)
	handle("POST /api/v1/sites/{id}/certificate", siteInPath, a.putCert)
	handle("POST /api/v1/sites/{id}/static", siteInPath, a.uploadStatic)
	handle("GET /api/v1/site-counts", adminOnly, a.siteCounts)
	// Global objects.
	handle("GET /api/v1/certificates", adminOnly, a.listCerts)
	handle("POST /api/v1/certificates", adminOnly, a.createCert)
	handle("PUT /api/v1/certificates/{id}", adminOnly, a.updateCert)
	handle("DELETE /api/v1/certificates/{id}", adminOnly, a.deleteCert)
	handle("GET /api/v1/ip-groups", adminOnly, a.listGroups)
	handle("POST /api/v1/ip-groups", adminOnly, a.createGroup)
	handle("PUT /api/v1/ip-groups/{id}", adminOnly, a.updateGroup)
	handle("DELETE /api/v1/ip-groups/{id}", adminOnly, a.deleteGroup)
	handle("GET /api/v1/rules", adminOnly, a.listRules)
	handle("POST /api/v1/rules", adminOnly, a.createRule)
	handle("PUT /api/v1/rules/{id}", adminOnly, a.updateRule)
	handle("DELETE /api/v1/rules/{id}", adminOnly, a.deleteRule)
	// Logs and statistics.
	handle("GET /api/v1/events", siteParam, a.events)
	handle("GET /api/v1/stats", siteParam, a.stats)
	handle("GET /api/v1/stats/overview", siteParam, a.overview)
	handle("GET /api/v1/attacks", siteParam, a.attacks)
	handle("GET /api/v1/attacks/groups", siteParam, a.attackGroups)
	handle("GET /api/v1/attacks/{tx}", txInPath, a.attackDetail)
	handle("GET /api/v1/logs", siteParam, a.logs)
	handle("GET /api/v1/logs/groups", siteParam, a.logGroups)
	handle("GET /api/v1/bans", siteParam, a.bans)
	handle("DELETE /api/v1/bans", siteParam, a.unban)
	handle("GET /api/v1/waitroom", adminOnly, a.waitRooms)
	handle("GET /api/v1/protections", anyCaller, a.protections)
	handle("GET /api/v1/apps", anyCaller, a.apps)
	handle("GET /api/v1/system", adminOnly, a.system)
	handle("GET /api/v1/rulesets", adminOnly, a.listRulesets)
	handle("PUT /api/v1/rulesets/active", adminOnly, a.setRuleset)
	handle("GET /api/v1/backups", adminOnly, a.listBackups)
	handle("POST /api/v1/backups", adminOnly, a.createBackup)
	handle("GET /api/v1/backups/{name}", adminOnly, a.downloadBackup)
	handle("GET /api/v1/alerts", adminOnly, a.getAlerts)
	handle("PUT /api/v1/alerts", adminOnly, a.putAlerts)
	handle("POST /api/v1/alerts/test", adminOnly, a.testAlert)
	// Console account.
	handle("POST /api/v1/auth/login", anyCaller, a.login)
	handle("POST /api/v1/auth/logout", adminOnly, a.logout)
	handle("GET /api/v1/auth/me", anyCaller, a.me)
	handle("POST /api/v1/auth/password", adminOnly, a.changePassword)
	handle("POST /api/v1/auth/totp/setup", adminOnly, a.totpSetup)
	handle("POST /api/v1/auth/totp/enable", adminOnly, a.totpEnable)
	handle("POST /api/v1/auth/totp/disable", adminOnly, a.totpDisable)
	handle("GET /api/v1/tokens", adminOnly, a.listTokens)
	handle("POST /api/v1/tokens", adminOnly, a.createToken)
	handle("DELETE /api/v1/tokens/{id}", adminOnly, a.deleteToken)
	return a.auth(mux)
}

// Sync compiles every stored site and loads the result into the engine.
func (a *API) Sync(ctx context.Context) error {
	return a.apply(ctx, func(*store.Tx) error { return nil })
}

// globals reads the global objects inside tx.
func globals(tx *store.Tx) (site.Globals, map[string]site.Cert, error) {
	g := site.Globals{Groups: map[string]site.IPGroup{}, Certs: map[string]site.Certificate{}}
	certs := map[string]site.Cert{}
	objs, err := tx.ListObjects(store.KindIPGroup)
	if err != nil {
		return g, nil, err
	}
	for _, o := range objs {
		var grp site.IPGroup
		if err := json.Unmarshal(o.Doc, &grp); err != nil {
			return g, nil, err
		}
		g.Groups[o.ID] = grp
	}
	if objs, err = tx.ListObjects(store.KindCert); err != nil {
		return g, nil, err
	}
	for _, o := range objs {
		var c site.Certificate
		if err := json.Unmarshal(o.Doc, &c); err != nil {
			return g, nil, err
		}
		g.Certs[o.ID] = c
		certs[o.ID] = site.Cert{CertPEM: c.CertPEM, KeyPEM: c.KeyPEM}
	}
	rules, err := listRules(tx)
	if err != nil {
		return g, nil, err
	}
	g.Rules = rules
	legacy, err := tx.Certs()
	if err != nil {
		return g, nil, err
	}
	for k, v := range legacy {
		certs[k] = v
	}
	return g, certs, nil
}

// apply runs fn and then rebuilds and loads the whole config, all inside one
// transaction: any error, including Caddy's, rolls fn's changes back. Only
// the *Tx may be used here; the store has a single connection.
func (a *API) apply(ctx context.Context, fn func(*store.Tx) error) error {
	err := a.st.Tx(ctx, func(tx *store.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		recs, err := tx.ListSites()
		if err != nil {
			return err
		}
		g, certs, err := globals(tx)
		if err != nil {
			return err
		}
		sites := make([]site.Resolved, 0, len(recs))
		for _, r := range recs {
			res := site.Resolve(r.ID, r.Doc)
			if err := site.ApplyGlobals(&res, g); err != nil {
				return err
			}
			sites = append(sites, res)
		}
		if err := site.ValidateAll(sites); err != nil {
			return err
		}
		opt := a.opt
		version, _, err := tx.Setting(rulesetKey)
		if err != nil {
			return err
		}
		if opt.CRSDir, err = a.rulesetDir(version); err != nil {
			return err
		}
		opt.PluginsDir = a.ops.PluginsDir
		cfg, err := compile.Config(sites, certs, opt)
		if err != nil {
			return &httpError{status: http.StatusBadRequest, msg: err.Error()}
		}
		return a.cl.Load(ctx, cfg)
	})
	if errors.Is(err, caddyclient.ErrUnreachable) {
		// The engine may still apply a load we stopped waiting for, which
		// would leave it running a config the database rolled back.
		go a.resync()
	}
	return err
}

// resync pushes the saved config until the engine takes it, so the engine
// ends up running what the database holds. Only one runs at a time.
func (a *API) resync() {
	if !a.resyncing.CompareAndSwap(false, true) {
		return
	}
	defer a.resyncing.Store(false)
	for i := 0; i < 20; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
		err := a.Sync(ctx) // waits for any running change: the store has one connection
		cancel()
		if err == nil {
			a.log.Info("engine put back to the saved config after an unanswered load")
			return
		}
		if !errors.Is(err, caddyclient.ErrUnreachable) {
			a.log.Error("resync after an unanswered load failed", "err", err)
			return
		}
		time.Sleep(a.resyncRetry)
	}
	a.log.Error("engine still unreachable; it may be running a config the database does not hold")
}

// --- errors ---------------------------------------------------------------

var errNotFound = &httpError{status: http.StatusNotFound, msg: "not found"}

type httpError struct {
	status     int
	msg, field string
}

func (e *httpError) Error() string { return e.msg }

func badRequest(field, msg string) error {
	return &httpError{status: http.StatusBadRequest, msg: msg, field: field}
}

type errBody struct {
	Error string `json:"error"`
	Field string `json:"field,omitempty"`
}

func (a *API) writeErr(w http.ResponseWriter, err error) {
	var he *httpError
	var ve *site.ValidationError
	var le *caddyclient.LoadError
	switch {
	case errors.As(err, &he):
		writeJSON(w, he.status, errBody{Error: he.msg, Field: he.field})
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, errBody{Error: ve.Msg, Field: ve.Field})
	case errors.Is(err, caddyclient.ErrUnreachable):
		writeJSON(w, http.StatusServiceUnavailable, errBody{Error: "the engine did not answer, so the change was not saved; the engine is being put back to the saved config"})
	case errors.As(err, &le):
		writeJSON(w, http.StatusBadGateway, errBody{Error: "engine rejected the config: " + caddyMessage(le.Body)})
	default:
		a.log.Error("api", "err", err)
		writeJSON(w, http.StatusInternalServerError, errBody{Error: "internal error"})
	}
}

// engineErr turns an admin API error answer on a non-config call (bans)
// into a neutral 502; writeErr's LoadError wording is about config loads.
func engineErr(err error) error {
	var le *caddyclient.LoadError
	if errors.As(err, &le) {
		return &httpError{status: http.StatusBadGateway, msg: "engine error: " + caddyMessage(le.Body)}
	}
	return err
}

// caddyMessage extracts the "error" field Caddy's admin API puts in its JSON
// error bodies, falling back to the raw text.
func caddyMessage(body string) string {
	var m struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(body), &m) == nil && m.Error != "" {
		return m.Error
	}
	return strings.TrimSpace(body)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decode reads one JSON value (at most 1 MiB, no unknown fields) into v.
func decode(w http.ResponseWriter, r *http.Request, v any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		var extra json.RawMessage
		if dec.Decode(&extra) != io.EOF {
			err = errors.New("unexpected data after the JSON body")
		}
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return &httpError{status: http.StatusRequestEntityTooLarge, msg: "request body exceeds 1 MiB"}
		}
		return badRequest("", "invalid JSON body: "+err.Error())
	}
	return nil
}

// page reads ?page= (1-based) and ?size= (default 20, max 200).
func page(r *http.Request) (limit, offset int) {
	q := r.URL.Query()
	size, _ := strconv.Atoi(q.Get("size"))
	if size <= 0 {
		size = 20
	}
	if size > 200 {
		size = 200
	}
	p, _ := strconv.Atoi(q.Get("page"))
	if p < 1 {
		p = 1
	}
	return size, (p - 1) * size
}

// timeRange reads ?since= and ?until= (RFC3339) or ?range= (a Go duration
// or 24h/7d/30d) back from now.
func timeRange(r *http.Request) (since, until time.Time, err error) {
	q := r.URL.Query()
	if s := q.Get("since"); s != "" {
		if since, err = time.Parse(time.RFC3339, s); err != nil {
			return since, until, badRequest("since", "must be an RFC3339 time")
		}
	}
	if s := q.Get("until"); s != "" {
		if until, err = time.Parse(time.RFC3339, s); err != nil {
			return since, until, badRequest("until", "must be an RFC3339 time")
		}
	}
	if s := q.Get("range"); s != "" && since.IsZero() {
		d, perr := parseRange(s)
		if perr != nil {
			return since, until, badRequest("range", "must be like 1h, 24h, 7d or 30d")
		}
		since = now().Add(-d)
	}
	return since, until, nil
}

func parseRange(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 1 || days > 366 {
			return 0, errors.New("bad range")
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, errors.New("bad range")
	}
	return d, nil
}

// --- sites ----------------------------------------------------------------

type siteView struct {
	ID       string       `json:"id"`
	Created  time.Time    `json:"created"`
	Updated  time.Time    `json:"updated"`
	Doc      site.Doc     `json:"doc"`
	Resolved resolvedView `json:"resolved"`
}

type portView struct {
	Port  int  `json:"port"`
	HTTPS bool `json:"https"`
}

type authUserView struct {
	Username string `json:"username"`
}

// resolvedView is site.Resolved in the document's shape and key names. A
// rate limit that is off is null. Password hashes are never shown.
type resolvedView struct {
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Project     string     `json:"project"`
	FloatingIP  string     `json:"floating_ip"`
	Type        string     `json:"type"`
	Domains     []string   `json:"domains"`
	Ports       []portView `json:"ports"`
	Upstreams   []string   `json:"upstreams"`
	LBPolicy    string     `json:"lb_policy"`
	Redirect    struct {
		URL          string `json:"url"`
		Code         int    `json:"code"`
		PreservePath bool   `json:"preserve_path"`
	} `json:"redirect"`
	Advanced struct {
		HSTS         bool `json:"hsts"`
		Gzip         bool `json:"gzip"`
		HTTPRedirect bool `json:"http_redirect"`
		KeepHost     bool `json:"keep_host"`
	} `json:"advanced"`
	TLS struct {
		Mode   string `json:"mode"`
		CertID string `json:"cert_id"`
	} `json:"tls"`
	WAF struct {
		Mode             string          `json:"mode"`
		Paranoia         int             `json:"paranoia"`
		AnomalyThreshold int             `json:"anomaly_threshold"`
		Protections      map[string]bool `json:"protections"`
		Apps             []string        `json:"apps"`
	} `json:"waf"`
	RateLimit struct {
		Access *ratelimit.Limit `json:"access"`
		Attack *ratelimit.Limit `json:"attack"`
		Error  *ratelimit.Limit `json:"error"`
	} `json:"rate_limit"`
	Access struct {
		AllowIPs       []string      `json:"allow_ips"`
		BlockIPs       []string      `json:"block_ips"`
		AllowCountries []string      `json:"allow_countries"`
		BlockCountries []string      `json:"block_countries"`
		BlockIPsFile   string        `json:"block_ips_file"`
		AllowGroups    []string      `json:"allow_groups"`
		BlockGroups    []string      `json:"block_groups"`
		Rules          []access.Rule `json:"rules"`
	} `json:"access"`
	BotChallenge struct {
		Enabled    bool `json:"enabled"`
		Difficulty int  `json:"difficulty"`
	} `json:"bot_challenge"`
	Auth struct {
		Enabled       bool           `json:"enabled"`
		Users         []authUserView `json:"users"`
		SessionTTLSec int            `json:"session_ttl_sec"`
	} `json:"auth"`
	WaitingRoom struct {
		Enabled       bool `json:"enabled"`
		MaxActive     int  `json:"max_active"`
		SessionTTLSec int  `json:"session_ttl_sec"`
	} `json:"waiting_room"`
	BlockPage struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	} `json:"block_page"`
	Exclusions []site.Exclusion `json:"exclusions"`
}

// stripSecrets returns d without auth password hashes.
func stripSecrets(d site.Doc) site.Doc {
	if d.Auth == nil {
		return d
	}
	au := *d.Auth
	au.Users = make([]site.AuthUserDoc, len(d.Auth.Users))
	for i, u := range d.Auth.Users {
		au.Users[i] = site.AuthUserDoc{Username: u.Username}
	}
	d.Auth = &au
	return d
}

func (a *API) view(rec store.SiteRecord) siteView {
	r := site.Resolve(rec.ID, rec.Doc)
	var v resolvedView
	v.Name, v.Description, v.Type, v.Domains, v.Upstreams = r.Name, r.Description, r.Type, r.Domains, r.Upstreams
	v.Project, v.FloatingIP = rec.Doc.Project, r.FloatingIP
	for _, p := range compilePorts(r, a.opt) {
		v.Ports = append(v.Ports, portView{Port: p.Port, HTTPS: p.HTTPS})
	}
	v.LBPolicy = r.LBPolicy
	v.Redirect.URL, v.Redirect.Code, v.Redirect.PreservePath = r.RedirectURL, r.RedirectCode, r.PreservePath
	v.Advanced.HSTS, v.Advanced.Gzip, v.Advanced.HTTPRedirect, v.Advanced.KeepHost = r.HSTS, r.Gzip, r.HTTPRedirect, r.KeepHost
	v.TLS.Mode, v.TLS.CertID = r.TLSMode, r.CertID
	v.WAF.Mode, v.WAF.Paranoia, v.WAF.AnomalyThreshold, v.WAF.Protections =
		r.WAFMode, r.Paranoia, r.AnomalyThreshold, r.Protections
	v.WAF.Apps = append([]string{}, r.Apps...)
	v.RateLimit.Access, v.RateLimit.Attack, v.RateLimit.Error = r.Access, r.Attack, r.Error
	v.Access.AllowIPs, v.Access.BlockIPs = r.AllowIPs, r.BlockIPs
	v.Access.AllowCountries, v.Access.BlockCountries = r.AllowCountries, r.BlockCountries
	v.Access.BlockIPsFile, v.Access.Rules = r.BlockIPsFile, r.Rules
	v.Access.AllowGroups, v.Access.BlockGroups = r.AllowGroups, r.BlockGroups
	v.BotChallenge.Enabled, v.BotChallenge.Difficulty = r.Challenge, r.ChallengeDifficulty
	v.Auth.Enabled, v.Auth.SessionTTLSec = r.AuthEnabled, r.AuthTTL
	v.Auth.Users = []authUserView{}
	for _, u := range r.AuthUsers {
		v.Auth.Users = append(v.Auth.Users, authUserView{Username: u.Username})
	}
	v.WaitingRoom.Enabled, v.WaitingRoom.MaxActive, v.WaitingRoom.SessionTTLSec = r.WaitEnabled, r.WaitMax, r.WaitTTL
	v.BlockPage.Title, v.BlockPage.Message = r.BlockTitle, r.BlockMessage
	v.Exclusions = append([]site.Exclusion{}, r.Exclusions...)
	return siteView{ID: rec.ID, Created: rec.Created, Updated: rec.Updated, Doc: stripSecrets(rec.Doc), Resolved: v}
}

// compilePorts mirrors the compiler's default ports for display.
func compilePorts(r site.Resolved, opt compile.Options) []site.PortDoc {
	if len(r.Ports) > 0 {
		return r.Ports
	}
	if r.TLSMode == "off" {
		return []site.PortDoc{{Port: opt.HTTPPort}}
	}
	return []site.PortDoc{{Port: opt.HTTPPort}, {Port: opt.HTTPSPort, HTTPS: true}}
}

// prepareDoc fills auth password hashes kept from prev (on update), validates
// d, then hashes new plain passwords. It runs inside the transaction.
func (a *API) prepareDoc(d *site.Doc, prev *site.Doc) error {
	if d.Auth != nil && prev != nil && prev.Auth != nil {
		old := map[string]string{}
		for _, u := range prev.Auth.Users {
			old[u.Username] = u.PasswordHash
		}
		for i, u := range d.Auth.Users {
			if u.Password == "" && u.PasswordHash == "" {
				d.Auth.Users[i].PasswordHash = old[u.Username]
			}
		}
	}
	if err := site.Validate(*d, a.opt.GeoIPDB != ""); err != nil {
		return err
	}
	if d.WAF != nil && len(d.WAF.Apps) > 0 && a.ops.PluginsDir == "" {
		return badRequest("waf.apps", "app profiles are not set up on this server")
	}
	if d.Auth != nil {
		for i, u := range d.Auth.Users {
			if u.Password != "" {
				h, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
				if err != nil {
					return err
				}
				d.Auth.Users[i] = site.AuthUserDoc{Username: u.Username, PasswordHash: string(h)}
			} else if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
				return &site.ValidationError{Field: "auth.users[" + strconv.Itoa(i) + "].password_hash", Msg: "is not a bcrypt hash"}
			}
		}
	}
	return nil
}

// now is millisecond-truncated, the precision the store keeps.
func now() time.Time { return time.Now().UTC().Truncate(time.Millisecond) }

// mutationCtx keeps a mutation running if the client disconnects, so the DB
// and the engine aren't left to a half-cancelled load.
func mutationCtx(r *http.Request) context.Context { return context.WithoutCancel(r.Context()) }

func (a *API) createSite(w http.ResponseWriter, r *http.Request) {
	var d site.Doc
	if err := decode(w, r, &d); err != nil {
		a.writeErr(w, err)
		return
	}
	p := principalOf(r)
	if err := tenantDoc(p, &d, nil); err != nil {
		a.writeErr(w, err)
		return
	}
	if err := site.Validate(d, a.opt.GeoIPDB != ""); err != nil {
		a.writeErr(w, err)
		return
	}
	if err := a.checkClaims(r.Context(), p, d, nil); err != nil {
		a.writeErr(w, err)
		return
	}
	t := now()
	rec := store.SiteRecord{ID: site.NewID(), Created: t, Updated: t}
	err := a.apply(mutationCtx(r), func(tx *store.Tx) error {
		if err := projectHasRoom(tx, d.Project); err != nil {
			return err
		}
		if err := a.prepareDoc(&d, nil); err != nil {
			return err
		}
		rec.Doc = d
		return tx.PutSite(rec)
	})
	if err != nil {
		a.writeErr(w, hideOthers(p, err))
		return
	}
	writeJSON(w, http.StatusCreated, a.view(rec))
}

// maxProjectSites caps one project's sites, so a customer can't load the shared
// engine with thousands of configs. Operator sites (no project) have no cap.
// shortcut: one cap for everyone, make it per plan when billing has plans.
var maxProjectSites = 100

// projectHasRoom counts inside the transaction, so parallel creates can't pass the cap together.
func projectHasRoom(tx *store.Tx, project string) error {
	if project == "" {
		return nil
	}
	recs, err := tx.ListSites()
	if err != nil {
		return err
	}
	n := 0
	for _, r := range recs {
		if r.Doc.Project == project {
			n++
		}
	}
	if n >= maxProjectSites {
		return &httpError{status: http.StatusForbidden, msg: fmt.Sprintf("this project already has the maximum of %d sites", maxProjectSites)}
	}
	return nil
}

func (a *API) listSites(w http.ResponseWriter, r *http.Request) {
	recs, err := a.st.ListSites(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	project := principalOf(r).Project
	out := make([]siteView, 0, len(recs))
	for _, rec := range recs {
		if project == "" || rec.Doc.Project == project {
			out = append(out, a.view(rec))
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) getSite(w http.ResponseWriter, r *http.Request) {
	var rec store.SiteRecord
	err := a.st.Tx(r.Context(), func(tx *store.Tx) error {
		got, ok, err := tx.GetSite(r.PathValue("id"))
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		rec = got
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, a.view(rec))
}

// replaceSite stores d as the site's document; merge, when set, builds the
// new document from the stored one.
func (a *API) replaceSite(w http.ResponseWriter, r *http.Request, merge func(stored site.Doc) (site.Doc, error)) {
	var rec store.SiteRecord
	err := a.apply(mutationCtx(r), func(tx *store.Tx) error {
		got, ok, err := tx.GetSite(r.PathValue("id"))
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		d, err := merge(got.Doc)
		if err != nil {
			return err
		}
		if err := tenantDoc(principalOf(r), &d, &got.Doc); err != nil {
			return err
		}
		// shortcut: DNS lookups inside the transaction hold the store's one connection
		// (5s at most per new domain); move them out if customers add domains often.
		if err := a.checkClaims(r.Context(), principalOf(r), d, &got.Doc); err != nil {
			return err
		}
		prev := got.Doc
		if err := a.prepareDoc(&d, &prev); err != nil {
			return err
		}
		rec = got // keeps ID and Created: PutSite overwrites created
		rec.Doc, rec.Updated = d, now()
		return tx.PutSite(rec)
	})
	if err != nil {
		a.writeErr(w, hideOthers(principalOf(r), err))
		return
	}
	writeJSON(w, http.StatusOK, a.view(rec))
}

func (a *API) putSite(w http.ResponseWriter, r *http.Request) {
	var d site.Doc
	if err := decode(w, r, &d); err != nil {
		a.writeErr(w, err)
		return
	}
	a.replaceSite(w, r, func(site.Doc) (site.Doc, error) { return d, nil })
}

// patchSite merges a partial document (top-level keys) into the stored one:
// the console uses it to change one tab without resending the rest.
func (a *API) patchSite(w http.ResponseWriter, r *http.Request) {
	var patch map[string]json.RawMessage
	if err := decode(w, r, &patch); err != nil {
		a.writeErr(w, err)
		return
	}
	a.replaceSite(w, r, func(stored site.Doc) (site.Doc, error) {
		b, err := json.Marshal(stored)
		if err != nil {
			return site.Doc{}, err
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal(b, &m); err != nil {
			return site.Doc{}, err
		}
		for k, v := range patch {
			if string(v) == "null" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		b, _ = json.Marshal(m)
		var d site.Doc
		dec := json.NewDecoder(strings.NewReader(string(b)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&d); err != nil {
			return site.Doc{}, badRequest("", "invalid patch: "+err.Error())
		}
		return d, nil
	})
}

// addExclusion appends one rule exception to a site (the console's "false
// alarm" button). Adding one the site already has changes nothing.
func (a *API) addExclusion(w http.ResponseWriter, r *http.Request) {
	var e site.Exclusion
	if err := decode(w, r, &e); err != nil {
		a.writeErr(w, err)
		return
	}
	e.Note = strings.TrimSpace(e.Note)
	a.replaceSite(w, r, func(d site.Doc) (site.Doc, error) {
		for _, x := range d.Exclusions {
			if x.RuleID == e.RuleID && x.PathExact == e.PathExact && x.PathPrefix == e.PathPrefix && x.Field == e.Field {
				return d, nil
			}
		}
		d.Exclusions = append(d.Exclusions, e)
		return d, nil
	})
}

func (a *API) deleteSite(w http.ResponseWriter, r *http.Request) {
	err := a.apply(mutationCtx(r), func(tx *store.Tx) error {
		ok, err := tx.DeleteSite(r.PathValue("id"))
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return nil
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- certificates ---------------------------------------------------------

type certReq struct {
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// certView describes a stored certificate; it never includes the key.
type certView struct {
	SiteID   string    `json:"site_id"`
	Subject  string    `json:"subject"`
	DNSNames []string  `json:"dns_names"`
	NotAfter time.Time `json:"not_after"`
}

func parsePair(certPEM, keyPEM string) (tls.Certificate, error) {
	if certPEM == "" {
		return tls.Certificate{}, badRequest("cert_pem", "is required")
	}
	if keyPEM == "" {
		return tls.Certificate{}, badRequest("key_pem", "is required")
	}
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return pair, badRequest("", "invalid certificate or key: "+err.Error())
	}
	return pair, nil
}

func (a *API) putCert(w http.ResponseWriter, r *http.Request) {
	var req certReq
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	pair, err := parsePair(req.CertPEM, req.KeyPEM)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	id := r.PathValue("id")
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error {
		_, ok, err := tx.GetSite(id)
		if err != nil {
			return err
		}
		if !ok {
			return errNotFound
		}
		return tx.PutCert(id, site.Cert{CertPEM: req.CertPEM, KeyPEM: req.KeyPEM})
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	cv := certView{SiteID: id}
	if leaf := pair.Leaf; leaf != nil { // set by X509KeyPair since Go 1.23
		cv.Subject, cv.DNSNames, cv.NotAfter = leaf.Subject.CommonName, leaf.DNSNames, leaf.NotAfter.UTC()
	}
	writeJSON(w, http.StatusOK, cv)
}

// --- events and stats -----------------------------------------------------

type eventView struct {
	ID       int64     `json:"id"`
	TS       time.Time `json:"ts"`
	SiteID   string    `json:"site_id"`
	Type     string    `json:"type"`
	ClientIP string    `json:"client_ip"`
	Country  string    `json:"country"`
	Host     string    `json:"host"`
	Method   string    `json:"method"`
	URI      string    `json:"uri"`
	RuleID   string    `json:"rule_id"`
	Detail   string    `json:"detail"`
	TxID     string    `json:"tx_id,omitempty"`
	Data     string    `json:"data,omitempty"`
	Severity int       `json:"severity,omitempty"`
	Category string    `json:"category,omitempty"`
}

func toEventView(e store.Event) eventView {
	v := eventView{ID: e.ID, TS: e.TS, SiteID: e.SiteID, Type: e.Type, ClientIP: e.ClientIP, Country: e.Country,
		Host: e.Host, Method: e.Method, URI: e.URI, RuleID: e.RuleID, Detail: e.Msg,
		TxID: e.TxID, Data: e.Data, Category: e.Category}
	if e.Severity != 9 {
		v.Severity = e.Severity
	}
	return v
}

func (a *API) events(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{SiteID: q.Get("site"), Type: q.Get("type"), IP: q.Get("ip")}
	if s := q.Get("since"); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			a.writeErr(w, badRequest("since", "must be an RFC3339 time"))
			return
		}
		f.Since = t
	}
	if s := q.Get("limit"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			a.writeErr(w, badRequest("limit", "must be a positive integer"))
			return
		}
		f.Limit = n
	}
	evs, err := a.st.QueryEvents(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := make([]eventView, 0, len(evs))
	for _, e := range evs {
		out = append(out, toEventView(e))
	}
	writeJSON(w, http.StatusOK, out)
}

type countView struct {
	Key     string `json:"key"`
	Count   int    `json:"count"`
	Blocked int    `json:"blocked,omitempty"`
}

type statsView struct {
	Since    time.Time      `json:"since"`
	ByType   map[string]int `json:"by_type"`
	TopIPs   []countView    `json:"top_ips"`
	TopRules []countView    `json:"top_rules"`
}

func counts(in []store.Count) []countView {
	out := make([]countView, 0, len(in))
	for _, c := range in {
		out = append(out, countView{Key: c.Key, Count: c.N, Blocked: c.Blocked})
	}
	return out
}

func (a *API) stats(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	window := 24 * time.Hour
	if s := q.Get("window"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil || d <= 0 {
			a.writeErr(w, badRequest("window", "must be a positive Go duration such as 24h"))
			return
		}
		window = d
	}
	since := now().Add(-window)
	st, err := a.st.Stats(r.Context(), q.Get("site"), since)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, statsView{Since: since, ByType: st.ByType,
		TopIPs: counts(st.TopIPs), TopRules: counts(st.TopRules)})
}

// --- bans -----------------------------------------------------------------

func (a *API) bans(w http.ResponseWriter, r *http.Request) {
	b, err := a.cl.Bans(r.Context(), r.URL.Query().Get("site"))
	if err != nil {
		a.writeErr(w, engineErr(err))
		return
	}
	if b == nil {
		b = map[string][]caddyclient.Ban{}
	}
	writeJSON(w, http.StatusOK, b)
}

func (a *API) unban(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	siteID, ip := q.Get("site"), q.Get("ip")
	if siteID == "" {
		a.writeErr(w, badRequest("site", "is required"))
		return
	}
	// The engine lists an IPv6 ban as its /64, so that form is accepted too.
	if _, err := netip.ParseAddr(ip); err != nil {
		if p, perr := netip.ParsePrefix(ip); perr != nil || !p.Addr().Is6() || p.Bits() != 64 {
			a.writeErr(w, badRequest("ip", "must be an IP address or an IPv6 /64"))
			return
		}
	}
	ok, err := a.cl.Unban(r.Context(), siteID, ip)
	if err != nil {
		a.writeErr(w, engineErr(err))
		return
	}
	if !ok {
		a.writeErr(w, &httpError{status: http.StatusNotFound, msg: "ip is not banned"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) waitRooms(w http.ResponseWriter, r *http.Request) {
	m, err := a.cl.WaitRooms(r.Context())
	if err != nil {
		a.writeErr(w, engineErr(err))
		return
	}
	writeJSON(w, http.StatusOK, m)
}

// --- protections ----------------------------------------------------------

type protectionView struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
}

// apps lists the app profiles; none when this manager has no plugins directory.
func (a *API) apps(w http.ResponseWriter, r *http.Request) {
	if a.ops.PluginsDir == "" {
		writeJSON(w, http.StatusOK, []crsplugins.App{})
		return
	}
	writeJSON(w, http.StatusOK, crsplugins.Catalog)
}

func (a *API) protections(w http.ResponseWriter, r *http.Request) {
	out := make([]protectionView, 0, len(site.Protections))
	for _, p := range site.Protections {
		out = append(out, protectionView{Key: p.Key, Label: p.Label, Default: p.Default})
	}
	writeJSON(w, http.StatusOK, out)
}
