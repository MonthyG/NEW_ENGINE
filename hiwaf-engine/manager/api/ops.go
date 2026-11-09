package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"hostinginside/waf/manager/alert"
	"hostinginside/waf/manager/backup"
	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

// Ops wires the operations features into the API. A nil Backups, Notifier or
// Watcher turns that feature off, and an empty RulesetsDir leaves the engine on
// its built-in rules.
type Ops struct {
	RulesetsDir string // holds unpacked CRS releases, one directory per version
	PluginsDir  string // the app profiles' CRS plugins (crsplugins.Install); empty turns profiles off
	Backups     *backup.Backups
	Notifier    *alert.Notifier
	Watcher     *alert.Watcher
}

// SetOps installs the operations features; call it before serving.
func (a *API) SetOps(o Ops) { a.ops = o }

// --- rule sets ---------------------------------------------------------------

// rulesetKey stores the active CRS version; empty or missing = built-in.
const rulesetKey = "ruleset"

var versionRE = regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}$`)

// rulesetDir returns the directory of an installed rule set, or "" for the
// built-in one. An unknown or incomplete version is an error, so a deleted
// directory is reported instead of being pushed to the engine.
func (a *API) rulesetDir(version string) (string, error) {
	if version == "" {
		return "", nil
	}
	if !versionRE.MatchString(version) || a.ops.RulesetsDir == "" {
		return "", badRequest("version", "unknown rule set "+strconv.Quote(version))
	}
	dir := filepath.Join(a.ops.RulesetsDir, version)
	for _, f := range []string{"crs-setup.conf.example", "rules/REQUEST-901-INITIALIZATION.conf"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			return "", badRequest("version", "rule set "+version+" is not installed (missing "+f+"); install it or switch back to the built-in rules")
		}
	}
	return filepath.ToSlash(dir), nil
}

// activeRuleset returns the stored active version ("" = built-in).
func (a *API) activeRuleset(ctx context.Context) string {
	v, _, _ := a.st.Setting(ctx, rulesetKey)
	return v
}

// rulesetName is how the console shows a version.
func rulesetName(version string) string {
	if version == "" {
		return Ruleset
	}
	return "CRS " + version
}

type rulesetView struct {
	Version string `json:"version"` // "" = built-in
	Name    string `json:"name"`
	Active  bool   `json:"active"`
}

type rulesetsView struct {
	Dir   string        `json:"dir"`
	Items []rulesetView `json:"items"`
}

func (a *API) listRulesets(w http.ResponseWriter, r *http.Request) {
	active := a.activeRuleset(r.Context())
	v := rulesetsView{Dir: a.ops.RulesetsDir, Items: []rulesetView{{Name: rulesetName(""), Active: active == ""}}}
	var found []string
	if ents, err := os.ReadDir(a.ops.RulesetsDir); err == nil && a.ops.RulesetsDir != "" {
		for _, e := range ents {
			if e.IsDir() && versionRE.MatchString(e.Name()) {
				if _, err := a.rulesetDir(e.Name()); err == nil {
					found = append(found, e.Name())
				}
			}
		}
	}
	sort.Slice(found, func(i, j int) bool { return newerVersion(found[i], found[j]) })
	for _, f := range found {
		v.Items = append(v.Items, rulesetView{Version: f, Name: rulesetName(f), Active: f == active})
	}
	writeJSON(w, http.StatusOK, v)
}

// newerVersion reports whether dotted version x sorts after y.
func newerVersion(x, y string) bool {
	xs, ys := strings.Split(x, "."), strings.Split(y, ".")
	for i := range xs {
		a, _ := strconv.Atoi(xs[i])
		b, _ := strconv.Atoi(ys[i])
		if a != b {
			return a > b
		}
	}
	return false
}

// setRuleset switches the engine to another rule set. The switch is one
// config load: Caddy starts the new config before it stops the old one, so no
// connection is dropped, and if the engine refuses the rules (a release that
// this Coraza can't parse) the setting rolls back and the old rules stay.
func (a *API) setRuleset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	if _, err := a.rulesetDir(req.Version); err != nil {
		a.writeErr(w, err)
		return
	}
	// The engine only parses the rules for sites that run the WAF. With none,
	// a release it can't load would be accepted now and break the next site.
	recs, err := a.st.ListSites(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	checked := false
	for _, rec := range recs {
		checked = checked || site.Resolve(rec.ID, rec.Doc).WAFMode != "off"
	}
	if !checked {
		a.writeErr(w, &httpError{status: http.StatusConflict, msg: "no site runs the WAF yet, so the engine can't check this rule set; add a site first"})
		return
	}
	err = a.apply(mutationCtx(r), func(tx *store.Tx) error { return tx.SetSetting(rulesetKey, req.Version) })
	if err != nil {
		a.writeErr(w, err)
		return
	}
	a.log.Info("rule set switched", "ruleset", rulesetName(req.Version))
	writeJSON(w, http.StatusOK, rulesetView{Version: req.Version, Name: rulesetName(req.Version), Active: true})
}

// --- backups -----------------------------------------------------------------

func (a *API) listBackups(w http.ResponseWriter, r *http.Request) {
	if a.ops.Backups == nil {
		writeJSON(w, http.StatusOK, []backup.File{})
		return
	}
	list, err := a.ops.Backups.List()
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) createBackup(w http.ResponseWriter, r *http.Request) {
	if a.ops.Backups == nil {
		a.writeErr(w, errNotFound)
		return
	}
	f, err := a.ops.Backups.Now(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, f)
}

// downloadBackup sends a backup file. It holds every secret the console has,
// so it is only ever sent to a signed-in user or API key holder (as every
// route here) and never cached.
func (a *API) downloadBackup(w http.ResponseWriter, r *http.Request) {
	if a.ops.Backups == nil {
		a.writeErr(w, errNotFound)
		return
	}
	name := r.PathValue("name")
	p, ok := a.ops.Backups.Path(name)
	if !ok {
		a.writeErr(w, errNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("Cache-Control", "no-store")
	http.ServeFile(w, r, p)
}

// --- alerts ------------------------------------------------------------------

type alertsView struct {
	WebhookURL      string     `json:"webhook_url"`
	HeartbeatURL    string     `json:"heartbeat_url"`
	EngineDownSince *time.Time `json:"engine_down_since,omitempty"`
}

func (a *API) getAlerts(w http.ResponseWriter, r *http.Request) {
	var v alertsView
	v.WebhookURL, _, _ = a.st.Setting(r.Context(), alert.WebhookKey)
	v.HeartbeatURL, _, _ = a.st.Setting(r.Context(), alert.HeartbeatKey)
	if a.ops.Watcher != nil {
		if t := a.ops.Watcher.DownSince(); !t.IsZero() {
			t = t.UTC()
			v.EngineDownSince = &t
		}
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *API) putAlerts(w http.ResponseWriter, r *http.Request) {
	var req struct {
		WebhookURL   string `json:"webhook_url"`
		HeartbeatURL string `json:"heartbeat_url"`
	}
	if err := decode(w, r, &req); err != nil {
		a.writeErr(w, err)
		return
	}
	req.WebhookURL, req.HeartbeatURL = strings.TrimSpace(req.WebhookURL), strings.TrimSpace(req.HeartbeatURL)
	if err := alert.ValidURL(req.WebhookURL); err != nil {
		a.writeErr(w, badRequest("webhook_url", "Webhook "+err.Error()))
		return
	}
	if err := alert.ValidURL(req.HeartbeatURL); err != nil {
		a.writeErr(w, badRequest("heartbeat_url", "Heartbeat "+err.Error()))
		return
	}
	err := a.st.Tx(r.Context(), func(tx *store.Tx) error {
		if err := tx.SetSetting(alert.WebhookKey, req.WebhookURL); err != nil {
			return err
		}
		return tx.SetSetting(alert.HeartbeatKey, req.HeartbeatURL)
	})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	a.getAlerts(w, r)
}

// testAlert sends a test message and reports what the webhook said.
func (a *API) testAlert(w http.ResponseWriter, r *http.Request) {
	if a.ops.Notifier == nil {
		a.writeErr(w, errNotFound)
		return
	}
	hook, _, _ := a.st.Setting(r.Context(), alert.WebhookKey)
	if hook == "" {
		a.writeErr(w, badRequest("webhook_url", "Save a webhook URL first"))
		return
	}
	if err := a.ops.Notifier.Send(r.Context(), "test", "this is a test alert from the console."); err != nil {
		a.writeErr(w, &httpError{status: http.StatusBadGateway, msg: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
}
