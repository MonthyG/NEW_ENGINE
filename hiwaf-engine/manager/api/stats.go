package api

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"hostinginside/waf/manager/store"
)

// --- Statistics page -----------------------------------------------------

type pointView struct {
	T        time.Time `json:"t"`
	Requests int       `json:"requests"`
	Blocked  int       `json:"blocked"`
}

type overviewView struct {
	Since      time.Time     `json:"since"`
	StepSec    int           `json:"step_sec"`
	Requests   int           `json:"requests"`
	PV         int           `json:"pv"`
	UV         int           `json:"uv"`
	UniqueIPs  int           `json:"unique_ips"`
	Blocked    int           `json:"blocked"`
	BlockedIPs int           `json:"blocked_ips"`
	Err4xx     int           `json:"err_4xx"`
	Err5xx     int           `json:"err_5xx"`
	Blocked4xx int           `json:"blocked_4xx"`
	Series     []pointView   `json:"series"`
	QPS        []pointView   `json:"qps"` // last 10 minutes, 10 s buckets, as requests per second ×10
	Countries  []countView   `json:"countries"`
	Status     []countView   `json:"status"`
	OS         []countView   `json:"os"`
	Browsers   []countView   `json:"browsers"`
	Referrers  []countView   `json:"referrers"`
	Sites      []countView   `json:"sites"`
	Pages      []countView   `json:"pages"`
	IPs        []countView   `json:"ips"`
	Attacks    []countView   `json:"attack_types"`
	Actions    []countView   `json:"actions"` // requests per WAF action (deny, rate_limit, auth, wait, challenge, block, allow; "" = passed)
	Rules      []ruleHitView `json:"rules"`   // WAF rules that matched most
	P95MS      float64       `json:"p95_ms"`  // 95th percentile request duration
}

type ruleHitView struct {
	ID       string `json:"id"`
	Msg      string `json:"msg"`
	Category string `json:"category"`
	Count    int    `json:"count"`
	Stopped  int    `json:"stopped"` // matches whose request was stopped; the rest were watched
}

// fill returns points for every step from since to until, zero where the
// store had nothing.
func fill(pts []store.Point, since, until time.Time, step time.Duration) []pointView {
	have := map[int64]store.Point{}
	for _, p := range pts {
		have[p.T.UnixMilli()] = p
	}
	ms := step.Milliseconds()
	start := since.UnixMilli() / ms * ms
	var out []pointView
	for t := start; t <= until.UnixMilli(); t += ms {
		p := have[t]
		out = append(out, pointView{T: time.UnixMilli(t).UTC(), Requests: p.Requests, Blocked: p.Blocked})
	}
	return out
}

// stepFor picks a series step giving 48-ish points.
func stepFor(window time.Duration) time.Duration {
	for _, s := range []time.Duration{time.Minute, 5 * time.Minute, 15 * time.Minute, 30 * time.Minute,
		time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour} {
		if window/s <= 60 {
			return s
		}
	}
	return 24 * time.Hour
}

func (a *API) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since, until, err := timeRange(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	end := until
	if end.IsZero() {
		end = now()
	}
	if since.IsZero() {
		since = end.Add(-24 * time.Hour)
	}
	f := store.RequestFilter{SiteID: r.URL.Query().Get("site"), Since: since, Until: until}
	o, err := a.st.Overview(ctx, f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	step := stepFor(end.Sub(since))
	pts, err := a.st.Series(ctx, f, step)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v := overviewView{Since: since, StepSec: int(step.Seconds()), Requests: o.Requests, PV: o.PV, UV: o.UV,
		UniqueIPs: o.UniqueIPs, Blocked: o.Blocked, BlockedIPs: o.BlockedIPs, Err4xx: o.Err4xx,
		Err5xx: o.Err5xx, Blocked4xx: o.Blocked4xx, Series: fill(pts, since, end, step)}

	qf := store.RequestFilter{SiteID: f.SiteID, Since: now().Add(-10 * time.Minute)}
	qpts, err := a.st.Series(ctx, qf, 10*time.Second)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v.QPS = fill(qpts, qf.Since, now(), 10*time.Second)

	tops := []struct {
		dim   store.TopDim
		limit int
		dst   *[]countView
	}{
		{store.DimCountry, 20, &v.Countries}, {store.DimStatus, 10, &v.Status},
		{store.DimSite, 10, &v.Sites}, {store.DimPage, 10, &v.Pages}, {store.DimIP, 10, &v.IPs},
		{store.DimAction, 20, &v.Actions},
	}
	for _, t := range tops {
		c, err := a.st.TopRequests(ctx, f, t.dim, t.limit)
		if err != nil {
			a.writeErr(w, err)
			return
		}
		*t.dst = counts(c)
	}
	uas, err := a.st.TopRequests(ctx, f, store.DimUA, 2000)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v.OS, v.Browsers = clientCounts(uas)
	refs, err := a.st.TopRequests(ctx, f, store.DimReferer, 2000)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v.Referrers = referrerCounts(refs)
	ac, err := a.st.AttackCounts(ctx, f.SiteID, since)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v.Attacks = counts(ac)
	hits, err := a.st.RuleHits(ctx, f.SiteID, since, 8)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v.Rules = make([]ruleHitView, 0, len(hits))
	for _, h := range hits {
		v.Rules = append(v.Rules, ruleHitView{ID: h.RuleID, Msg: h.Msg, Category: h.Category, Count: h.N, Stopped: h.Stopped})
	}
	if v.P95MS, err = a.st.LatencyP95(ctx, f); err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// regroup sums counts by key(c) and returns the top n.
func regroup(in []store.Count, n int, key func(string) string) []countView {
	sum := map[string]*countView{}
	for _, c := range in {
		k := key(c.Key)
		v, ok := sum[k]
		if !ok {
			v = &countView{Key: k}
			sum[k] = v
		}
		v.Count += c.N
		v.Blocked += c.Blocked
	}
	out := make([]countView, 0, len(sum))
	for _, v := range sum {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func clientCounts(uas []store.Count) (os, browsers []countView) {
	return regroup(uas, 8, uaOS), regroup(uas, 8, uaBrowser)
}

func referrerCounts(refs []store.Count) []countView {
	return regroup(refs, 10, func(ref string) string {
		if ref == "" {
			return "-"
		}
		u, err := url.Parse(ref)
		if err != nil || u.Host == "" {
			return "-"
		}
		return strings.ToLower(u.Host)
	})
}

func uaOS(ua string) string {
	switch l := strings.ToLower(ua); {
	case ua == "":
		return "Unknown"
	case strings.Contains(l, "android"):
		return "Android"
	case strings.Contains(l, "iphone") || strings.Contains(l, "ipad") || strings.Contains(l, "ios"):
		return "iOS"
	case strings.Contains(l, "windows"):
		return "Windows"
	case strings.Contains(l, "mac os") || strings.Contains(l, "macintosh"):
		return "MacOS"
	case strings.Contains(l, "linux"):
		return "Linux"
	case isBot(l):
		return "Bot"
	}
	return "Other"
}

func isBot(l string) bool {
	for _, b := range []string{"bot", "spider", "crawl", "curl", "wget", "python", "go-http", "scanner", "nikto", "sqlmap", "zgrab", "masscan"} {
		if strings.Contains(l, b) {
			return true
		}
	}
	return false
}

func uaBrowser(ua string) string {
	switch l := strings.ToLower(ua); {
	case ua == "":
		return "Unknown"
	case isBot(l):
		switch {
		case strings.Contains(l, "curl"):
			return "curl"
		case strings.Contains(l, "python"):
			return "Python"
		case strings.Contains(l, "googlebot"):
			return "Googlebot"
		}
		return "Bot"
	case strings.Contains(l, "edg/"):
		return "Edge"
	case strings.Contains(l, "opr/") || strings.Contains(l, "opera"):
		return "Opera"
	case strings.Contains(l, "firefox"):
		return "Firefox"
	case strings.Contains(l, "chrome") && strings.Contains(l, "mobile"):
		return "Chrome Mobile"
	case strings.Contains(l, "chrome"):
		return "Chrome"
	case strings.Contains(l, "safari"):
		return "Safari"
	case strings.HasPrefix(l, "mozilla"):
		return "Mozilla"
	}
	return "Other"
}

type siteCountView struct {
	Requests int `json:"requests"`
	Blocked  int `json:"blocked"` // refused or stopped for any reason
	Threats  int `json:"threats"` // stopped by the WAF
}

// siteCounts returns today's (server local midnight) counts per site, for
// the application cards.
func (a *API) siteCounts(w http.ResponseWriter, r *http.Request) {
	t := time.Now()
	midnight := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
	m, err := a.st.SiteCounts(r.Context(), midnight)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := map[string]siteCountView{}
	for k, c := range m {
		out[k] = siteCountView{Requests: c.Requests, Blocked: c.Blocked, Threats: c.Threats}
	}
	writeJSON(w, http.StatusOK, out)
}

// --- Attacks page --------------------------------------------------------

type pageView[T any] struct {
	Items []T `json:"items"`
	Total int `json:"total"`
}

type attackView struct {
	TxID       string    `json:"tx_id"`
	TS         time.Time `json:"ts"`
	SiteID     string    `json:"site_id"`
	ClientIP   string    `json:"client_ip"`
	Country    string    `json:"country"`
	Categories []string  `json:"categories"`
	Matches    int       `json:"matches"`
	Severity   int       `json:"severity"`
	RuleID     string    `json:"rule_id"`
	Msg        string    `json:"msg"`
	Data       string    `json:"data"`
	Blocked    bool      `json:"blocked"`
	Method     string    `json:"method"`
	Host       string    `json:"host"`
	URI        string    `json:"uri"`
	Status     int       `json:"status"`
}

func attackFilter(r *http.Request) (store.AttackFilter, error) {
	since, until, err := timeRange(r)
	if err != nil {
		return store.AttackFilter{}, err
	}
	q := r.URL.Query()
	limit, offset := page(r)
	return store.AttackFilter{SiteID: q.Get("site"), IP: q.Get("ip"), Category: q.Get("category"),
		Since: since, Until: until, Limit: limit, Offset: offset}, nil
}

func (a *API) attacks(w http.ResponseWriter, r *http.Request) {
	f, err := attackFilter(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	items, total, err := a.st.Attacks(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := pageView[attackView]{Items: make([]attackView, 0, len(items)), Total: total}
	for _, x := range items {
		cats := x.Categories
		if cats == nil {
			cats = []string{}
		}
		out.Items = append(out.Items, attackView{TxID: x.TxID, TS: x.TS, SiteID: x.SiteID, ClientIP: x.ClientIP,
			Country: x.Country, Categories: cats, Matches: x.Matches, Severity: x.Severity, RuleID: x.RuleID,
			Msg: x.Msg, Data: x.Data, Blocked: x.Blocked, Method: x.Method, Host: x.Host, URI: x.URI, Status: x.Status})
	}
	writeJSON(w, http.StatusOK, out)
}

type groupRowView struct {
	SiteID   string    `json:"site_id"`
	ClientIP string    `json:"client_ip"`
	Country  string    `json:"country"`
	Count    int       `json:"count"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
}

func groupRows(gs []store.Group, total int) pageView[groupRowView] {
	out := pageView[groupRowView]{Items: make([]groupRowView, 0, len(gs)), Total: total}
	for _, g := range gs {
		out.Items = append(out.Items, groupRowView{SiteID: g.SiteID, ClientIP: g.ClientIP, Country: g.Country, Count: g.Count, First: g.First, Last: g.Last})
	}
	return out
}

func (a *API) attackGroups(w http.ResponseWriter, r *http.Request) {
	f, err := attackFilter(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	gs, total, err := a.st.AttackGroups(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, groupRows(gs, total))
}

type requestView struct {
	TS       time.Time `json:"ts"`
	SiteID   string    `json:"site_id"`
	ClientIP string    `json:"client_ip"`
	Country  string    `json:"country"`
	Method   string    `json:"method"`
	Host     string    `json:"host"`
	URI      string    `json:"uri"`
	Status   int       `json:"status"`
	Bytes    int64     `json:"bytes"`
	DurMS    float64   `json:"duration_ms"`
	UA       string    `json:"user_agent"`
	Referer  string    `json:"referer"`
	Action   string    `json:"action"`
}

type attackDetailView struct {
	TxID    string       `json:"tx_id"`
	Blocked bool         `json:"blocked"`
	Request *requestView `json:"request"`
	Matches []eventView  `json:"matches"`
}

func (a *API) attackDetail(w http.ResponseWriter, r *http.Request) {
	tx := r.PathValue("tx")
	evs, err := a.st.QueryEvents(r.Context(), store.EventFilter{TxID: tx, Limit: 500})
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if len(evs) == 0 {
		a.writeErr(w, errNotFound)
		return
	}
	v := attackDetailView{TxID: tx, Matches: []eventView{}}
	for i := len(evs) - 1; i >= 0; i-- { // oldest first
		e := evs[i]
		if e.Type == "waf_block" {
			v.Blocked = true
			continue
		}
		v.Matches = append(v.Matches, toEventView(e))
	}
	req, ok, err := a.st.RequestByTx(r.Context(), tx)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	if ok {
		v.Request = &requestView{TS: req.TS, SiteID: req.SiteID, ClientIP: req.ClientIP, Country: req.Country,
			Method: req.Method, Host: req.Host, URI: req.URI, Status: req.Status, Bytes: req.Bytes,
			DurMS: req.DurMS, UA: req.UA, Referer: req.Referer, Action: req.Action}
		v.Blocked = v.Blocked || req.Action == "block"
	}
	writeJSON(w, http.StatusOK, v)
}

// --- generic event logs (Allow & Deny, HTTP Flood, Anti-Bot, Auth) ---------

func logFilter(r *http.Request) (store.EventFilter, error) {
	since, until, err := timeRange(r)
	if err != nil {
		return store.EventFilter{}, err
	}
	q := r.URL.Query()
	limit, offset := page(r)
	f := store.EventFilter{SiteID: q.Get("site"), IP: q.Get("ip"), Since: since, Until: until, Limit: limit, Offset: offset}
	for _, t := range strings.Split(q.Get("types"), ",") {
		if t = strings.TrimSpace(t); t != "" {
			f.Types = append(f.Types, t)
		}
	}
	return f, nil
}

func (a *API) logs(w http.ResponseWriter, r *http.Request) {
	f, err := logFilter(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	evs, err := a.st.QueryEvents(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	total, err := a.st.CountEvents(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	out := pageView[eventView]{Items: make([]eventView, 0, len(evs)), Total: total}
	for _, e := range evs {
		out.Items = append(out.Items, toEventView(e))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) logGroups(w http.ResponseWriter, r *http.Request) {
	f, err := logFilter(r)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	gs, total, err := a.st.EventGroups(r.Context(), f)
	if err != nil {
		a.writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, groupRows(gs, total))
}

// --- system ----------------------------------------------------------------

type systemView struct {
	Version     string    `json:"version"`
	Started     time.Time `json:"started"`
	EngineOK    bool      `json:"engine_ok"`
	EngineError string    `json:"engine_error,omitempty"`
	GeoIP       bool      `json:"geoip"`
	AccessLog   bool      `json:"access_log"`
	StaticSites bool      `json:"static_sites"`
	HTTPPort    int       `json:"http_port"`
	HTTPSPort   int       `json:"https_port"`
	Sites       int       `json:"sites"`
	Ruleset     string    `json:"ruleset"`
}

func (a *API) system(w http.ResponseWriter, r *http.Request) {
	v := systemView{Version: Version, Ruleset: rulesetName(a.activeRuleset(r.Context())), Started: a.started.UTC(), GeoIP: a.opt.GeoIPDB != "",
		AccessLog: a.opt.AccessLog != "", StaticSites: a.opt.StaticDir != "",
		HTTPPort: a.opt.HTTPPort, HTTPSPort: a.opt.HTTPSPort}
	if _, err := a.cl.WaitRooms(r.Context()); err != nil {
		v.EngineError = err.Error()
	} else {
		v.EngineOK = true
	}
	recs, err := a.st.ListSites(r.Context())
	if err != nil {
		a.writeErr(w, err)
		return
	}
	v.Sites = len(recs)
	writeJSON(w, http.StatusOK, v)
}
