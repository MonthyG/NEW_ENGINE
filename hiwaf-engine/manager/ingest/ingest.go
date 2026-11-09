// Package ingest tails the engine's JSON logs: security events into the
// events table, access-log lines into the requests table.
package ingest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"hostinginside/waf/manager/site"
	"hostinginside/waf/manager/store"
)

const (
	offsetKey    = "ingest_offset"
	maxLineBytes = 1 << 20
	batchSize    = 500
	maxURI       = 2048
	maxText      = 512
)

var siteRe = regexp.MustCompile(`^s_[0-9a-f]{12}$`)

// unquote undoes the escaping Coraza applies to logged values.
func unquote(v string) string {
	if u, err := strconv.Unquote(`"` + v + `"`); err == nil {
		return u
	}
	return v
}

var corazaField = regexp.MustCompile(`\[(\w+) "((?:[^"\\]|\\.)*)"\]`)

// severities maps Coraza's severity names to syslog levels.
var severities = map[string]int{
	"emergency": 0, "alert": 1, "critical": 2, "error": 3,
	"warning": 4, "notice": 5, "info": 6, "debug": 7,
}

// Category returns the protection key covering a CRS rule ID, "score" for
// the anomaly-scoring rules, or "".
func Category(ruleID string) string {
	n, err := strconv.Atoi(ruleID)
	if err != nil {
		return ""
	}
	switch n / 1000 {
	case 949, 959, 980:
		return "score"
	}
	for _, p := range site.Protections {
		for _, r := range p.IDRanges {
			lo, hi, _ := strings.Cut(r, "-")
			l, _ := strconv.Atoi(lo)
			h, _ := strconv.Atoi(hi)
			if n >= l && n <= h {
				return p.Key
			}
		}
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func lineTS(m map[string]any) time.Time {
	if f, ok := m["ts"].(float64); ok {
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).UTC()
	}
	return time.Now().UTC()
}

// ParseLine converts one Caddy JSON log line into an Event; ok is false for
// lines that are not security events.
func ParseLine(line []byte) (store.Event, bool) {
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(line), &m); err != nil {
		return store.Event{}, false
	}
	str := func(k string) string { s, _ := m[k].(string); return s }
	ts := lineTS(m)

	if str("msg") == "hi_event" {
		return store.Event{
			TS: ts, SiteID: str("site_id"), Type: str("event"), ClientIP: str("client_ip"),
			Host: str("host"), Method: str("method"), URI: truncate(str("uri"), maxURI),
			RuleID: str("rule_id"), Msg: truncate(str("detail"), maxText), TxID: str("tx_id"),
		}, true
	}

	if str("logger") != "http.handlers.waf" {
		return store.Event{}, false
	}
	text := str("msg") // only msg: other fields may carry attacker-controlled data
	if !strings.Contains(text, `[id "`) {
		return store.Event{}, false
	}
	f := map[string]string{}
	for _, sm := range corazaField.FindAllStringSubmatch(text, -1) {
		if _, dup := f[sm[1]]; !dup {
			f[sm[1]] = unquote(sm[2])
		}
	}
	tx := f["unique_id"]
	siteID, _, _ := strings.Cut(tx, "-")
	if !siteRe.MatchString(siteID) {
		return store.Event{}, false
	}
	sev, ok := severities[strings.ToLower(f["severity"])]
	if !ok {
		sev = 9
	}
	return store.Event{
		TS: ts, SiteID: siteID, Type: "waf_match", ClientIP: f["client"],
		Host: f["hostname"], URI: truncate(f["uri"], maxURI), RuleID: f["id"], Msg: truncate(f["msg"], maxText),
		TxID: tx, Data: truncate(f["data"], maxText), Severity: sev, Category: Category(f["id"]),
	}, true
}

// accessLine is the part of a Caddy access log entry we keep.
type accessLine struct {
	TS      float64 `json:"ts"`
	Logger  string  `json:"logger"`
	Request struct {
		RemoteIP string              `json:"remote_ip"`
		ClientIP string              `json:"client_ip"`
		Method   string              `json:"method"`
		Host     string              `json:"host"`
		URI      string              `json:"uri"`
		Headers  map[string][]string `json:"headers"`
	} `json:"request"`
	Duration    float64             `json:"duration"`
	Size        int64               `json:"size"`
	Status      int                 `json:"status"`
	RespHeaders map[string][]string `json:"resp_headers"`
	Action      string              `json:"hi_action"`
	Kind        string              `json:"hi_type"`
	Tx          string              `json:"hi_tx"`
}

const accessPrefix = "http.log.access."

// ParseAccess converts one Caddy access log line into a Request; ok is false
// for other lines and for hosts not mapped to a site.
func ParseAccess(line []byte) (store.Request, bool) {
	var a accessLine
	if err := json.Unmarshal(bytes.TrimSpace(line), &a); err != nil {
		return store.Request{}, false
	}
	siteID, ok := strings.CutPrefix(a.Logger, accessPrefix)
	if !ok || !siteRe.MatchString(siteID) {
		return store.Request{}, false
	}
	first := func(h map[string][]string, k string) string {
		if v := h[k]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	ip := a.Request.ClientIP
	if ip == "" {
		ip = a.Request.RemoteIP
	}
	host := strings.ToLower(a.Request.Host)
	if h, _, found := strings.Cut(host, ":"); found && !strings.Contains(h, "]") && strings.Count(host, ":") == 1 {
		host = h
	}
	sec, frac := math.Modf(a.TS)
	return store.Request{
		TS:       time.Unix(int64(sec), int64(math.Round(frac*1e6))*1000).UTC(),
		SiteID:   siteID,
		ClientIP: ip,
		Method:   a.Request.Method,
		Host:     host,
		URI:      truncate(a.Request.URI, maxURI),
		Status:   a.Status,
		Bytes:    a.Size,
		DurMS:    a.Duration * 1000,
		UA:       truncate(first(a.Request.Headers, "User-Agent"), maxText),
		Referer:  truncate(first(a.Request.Headers, "Referer"), maxText),
		HTML:     strings.HasPrefix(first(a.RespHeaders, "Content-Type"), "text/html"),
		Action:   a.Action,
		Kind:     a.Kind,
		TxID:     a.Tx,
	}, true
}

// Tailer follows a log file and persists events (or, with Access, requests)
// plus its read offset.
type Tailer struct {
	Path      string
	Store     *store.Store
	Interval  time.Duration          // default 1s
	Logger    *slog.Logger           // default slog.Default()
	OffsetKey string                 // settings key of the read offset; default "ingest_offset"
	Access    bool                   // the file is a Caddy access log
	Country   func(ip string) string // optional GeoIP lookup
}

func (t *Tailer) key() string {
	if t.OffsetKey != "" {
		return t.OffsetKey
	}
	return offsetKey
}

// Once reads all complete lines added since the saved offset. The offset is
// saved after each batch is inserted, so a crash can at worst re-insert a batch.
func (t *Tailer) Once(ctx context.Context) error {
	f, err := os.Open(t.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	var saved int64
	s, ok, err := t.Store.Setting(ctx, t.key())
	if err != nil {
		return err
	}
	if ok {
		saved, _ = strconv.ParseInt(s, 10, 64)
	}
	off := saved
	if off < 0 || fi.Size() < off { // rotated or truncated
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return err
	}

	var evs []store.Event
	var reqs []store.Request
	flush := func(newOff int64) error {
		if err := t.Store.InsertEvents(ctx, evs); err != nil {
			return err
		}
		if err := t.Store.InsertRequests(ctx, reqs); err != nil {
			return err
		}
		evs, reqs = evs[:0], reqs[:0]
		if err := t.Store.SetSetting(ctx, t.key(), strconv.FormatInt(newOff, 10)); err != nil {
			return err
		}
		saved = newOff
		return nil
	}
	country := func(ip string) string {
		if t.Country == nil || ip == "" {
			return ""
		}
		return t.Country(ip)
	}

	r := bufio.NewReaderSize(f, 64<<10)
	var buf []byte
	skipping := false // current line exceeded maxLineBytes: discard it
	consumed := off   // offset just past the last complete line handled
	pos := off        // bytes read so far
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		chunk, err := r.ReadSlice('\n')
		pos += int64(len(chunk))
		if !skipping {
			buf = append(buf, chunk...)
			if len(buf) > maxLineBytes {
				skipping, buf = true, buf[:0]
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return err
			}
			break // a trailing partial line stays unconsumed
		}
		if !skipping {
			evs, reqs = parseInto(bytes.TrimRight(buf, "\r\n"), t.Access, country, evs, reqs)
		}
		buf, skipping = buf[:0], false
		consumed = pos
		if len(evs)+len(reqs) >= batchSize {
			if err := flush(consumed); err != nil {
				return err
			}
		}
	}
	if len(evs)+len(reqs) > 0 || consumed != saved {
		return flush(consumed)
	}
	return nil
}

// parseInto appends line, parsed as an access line or an event, to reqs or evs.
func parseInto(line []byte, access bool, country func(string) string, evs []store.Event, reqs []store.Request) ([]store.Event, []store.Request) {
	if access {
		if rq, ok := ParseAccess(line); ok {
			rq.Country = country(rq.ClientIP)
			reqs = append(reqs, rq)
		}
	} else if ev, ok := ParseLine(line); ok {
		ev.Country = country(ev.ClientIP)
		evs = append(evs, ev)
	}
	return evs, reqs
}

// Run calls Once every Interval until ctx is done.
func (t *Tailer) Run(ctx context.Context) error {
	iv := t.Interval
	if iv <= 0 {
		iv = time.Second
	}
	log := t.Logger
	if log == nil {
		log = slog.Default()
	}
	tick := time.NewTicker(iv)
	defer tick.Stop()
	for {
		if err := t.Once(ctx); err != nil && ctx.Err() == nil {
			log.Error("ingest", "path", t.Path, "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
		}
	}
}
