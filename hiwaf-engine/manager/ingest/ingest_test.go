package ingest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hostinginside/waf/manager/store"
)

func TestParseHiEvent(t *testing.T) {
	ev, ok := ParseLine([]byte(`{"ts":1761200000.5,"logger":"http.handlers.hi_access","msg":"hi_event","event":"ip_block","site_id":"s_aaaaaaaaaaaa","client_ip":"1.2.3.4","detail":"why"}` + "\r"))
	if !ok {
		t.Fatal("not parsed")
	}
	want := time.Date(2025, 10, 23, 6, 13, 20, 500_000_000, time.UTC)
	if ev.Type != "ip_block" || ev.SiteID != "s_aaaaaaaaaaaa" || ev.ClientIP != "1.2.3.4" || ev.Msg != "why" || !ev.TS.Equal(want) {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestParseCorazaMatch(t *testing.T) {
	line := `{"ts":1761200002,"logger":"http.handlers.waf","msg":"[client \"1.2.3.4\"] Coraza: Warning. SQL Injection Attack Detected [file \"x\"] [line \"1\"] [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [uri \"/?id=1\"] [unique_id \"s_aaaaaaaaaaaa-0123456789abcdef\"]"}`
	ev, ok := ParseLine([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	if ev.Type != "waf_match" || ev.RuleID != "942100" || ev.SiteID != "s_aaaaaaaaaaaa" || ev.ClientIP != "1.2.3.4" ||
		ev.URI != "/?id=1" || ev.Msg != "SQL Injection Attack Detected via libinjection" {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestParseIgnoresOther(t *testing.T) {
	for _, l := range []string{
		`{"ts":1,"logger":"http.log.access","msg":"handled request"}`,
		`{"ts":1,"logger":"http.handlers.waf","msg":"WAF rule violation detected"}`,
		`not json`,
		``,
	} {
		if ev, ok := ParseLine([]byte(l)); ok {
			t.Errorf("%q parsed as %+v", l, ev)
		}
	}
}

func TestParseFixture(t *testing.T) {
	b, err := os.ReadFile("testdata/events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if ev, ok := ParseLine([]byte(l)); ok {
			types = append(types, ev.Type)
		}
	}
	if got := strings.Join(types, ","); got != "ip_block,waf_match,rate_limit_ban" {
		t.Fatalf("types = %s", got)
	}
}

func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

func TestTailerOffsetAndRotation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := filepath.Join(dir, "events.log")
	tl := &Tailer{Path: log, Store: st}

	line := func(ip string) string {
		return `{"ts":1761200000,"msg":"hi_event","event":"ip_block","site_id":"s_aaaaaaaaaaaa","client_ip":"` + ip + `"}`
	}
	count := func(want int) {
		t.Helper()
		evs, err := st.QueryEvents(ctx, store.EventFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		if len(evs) != want {
			t.Fatalf("events = %d, want %d", len(evs), want)
		}
	}

	if err := tl.Once(ctx); err != nil { // missing file is fine
		t.Fatal(err)
	}
	appendFile(t, log, line("1.1.1.1")+"\r\n"+line("2.2.2.2")+"\n")
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(2)

	part := line("3.3.3.3")
	appendFile(t, log, part[:20])
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(2)

	appendFile(t, log, part[20:]+"\n")
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(3)

	if err := tl.Once(ctx); err != nil { // nothing new: no duplicates
		t.Fatal(err)
	}
	count(3)

	if err := os.WriteFile(log, []byte(line("4.4.4.4")+"\n"), 0o644); err != nil { // truncated: smaller than offset
		t.Fatal(err)
	}
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	count(4)
}

func TestTailerSkipsHugeLine(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	log := filepath.Join(dir, "events.log")
	huge := strings.Repeat("x", 2<<20)
	good := `{"ts":1761200000,"msg":"hi_event","event":"geo_block","site_id":"s_aaaaaaaaaaaa"}`
	appendFile(t, log, huge+"\n"+good+"\n")
	tl := &Tailer{Path: log, Store: st}
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	evs, err := st.QueryEvents(ctx, store.EventFilter{Limit: 10})
	if err != nil || len(evs) != 1 || evs[0].Type != "geo_block" {
		t.Fatalf("evs = %+v err = %v", evs, err)
	}
}

func TestParseCorazaHardening(t *testing.T) {
	mk := func(uid string) string {
		return `{"logger":"http.handlers.waf","msg":"[id \"1\"] [unique_id \"` + uid + `\"]"}`
	}
	for _, uid := range []string{"-abc", "garbage-0123", "s_AAAAAAAAAAAA-1", "nodash"} {
		if ev, ok := ParseLine([]byte(mk(uid))); ok {
			t.Errorf("unique_id %q parsed as %+v", uid, ev)
		}
	}
	if _, ok := ParseLine([]byte(`{"logger":"http.handlers.waf","msg":"x","other":"[id \"1\"] [unique_id \"s_aaaaaaaaaaaa-1\"]"}`)); ok {
		t.Error("non-msg field must not produce a match")
	}
	ev, ok := ParseLine([]byte(`{"logger":"http.handlers.waf","msg":"[id \"1\"] [msg \"say \\\"hi\\\"\"] [unique_id \"s_aaaaaaaaaaaa-1\"]"}`))
	if !ok || ev.Msg != `say "hi"` {
		t.Errorf("ev = %+v ok = %v", ev, ok)
	}
}

func TestParseCorazaMatchEnriched(t *testing.T) {
	line := `{"ts":1761200002,"logger":"http.handlers.waf","msg":"[client \"1.2.3.4\"] Coraza: Warning. x [id \"942100\"] [msg \"SQLi\"] [data \"Matched Data: 1' OR found within ARGS:id\"] [severity \"critical\"] [hostname \"Shop.Example.com\"] [uri \"/?id=1\"] [unique_id \"s_aaaaaaaaaaaa-0123456789abcdef\"]"}`
	ev, ok := ParseLine([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	if ev.TxID != "s_aaaaaaaaaaaa-0123456789abcdef" || ev.Severity != 2 || ev.Category != "sqli" ||
		ev.Data != "Matched Data: 1' OR found within ARGS:id" || ev.Host != "Shop.Example.com" {
		t.Fatalf("ev = %+v", ev)
	}
}

func TestCategory(t *testing.T) {
	for id, want := range map[string]string{"942100": "sqli", "941110": "xss", "949110": "score",
		"980170": "score", "920350": "protocol", "911100": "", "x": ""} {
		if got := Category(id); got != want {
			t.Errorf("Category(%s) = %q, want %q", id, got, want)
		}
	}
}

func TestParseAccess(t *testing.T) {
	line := `{"level":"info","ts":1761200000.25,"logger":"http.log.access.s_aaaaaaaaaaaa","msg":"handled request",` +
		`"request":{"remote_ip":"10.0.0.1","client_ip":"1.2.3.4","method":"GET","host":"Shop.example.com:8443","uri":"/p?q=1",` +
		`"headers":{"User-Agent":["Mozilla/5.0"],"Referer":["https://google.com/"]}},"duration":0.012,"size":512,"status":403,` +
		`"resp_headers":{"Content-Type":["text/html; charset=utf-8"]},"hi_action":"block","hi_type":"waf_block","hi_tx":"s_aaaaaaaaaaaa-01"}`
	r, ok := ParseAccess([]byte(line))
	if !ok {
		t.Fatal("not parsed")
	}
	if r.SiteID != "s_aaaaaaaaaaaa" || r.ClientIP != "1.2.3.4" || r.Host != "shop.example.com" || r.Status != 403 ||
		r.Action != "block" || r.TxID != "s_aaaaaaaaaaaa-01" || !r.HTML || r.UA != "Mozilla/5.0" ||
		r.Referer != "https://google.com/" || r.DurMS != 12 || r.Bytes != 512 {
		t.Fatalf("r = %+v", r)
	}
	if _, ok := ParseAccess([]byte(`{"logger":"http.log.access","request":{}}`)); ok {
		t.Fatal("unmapped access line parsed")
	}
}

func TestTailerAccessLog(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	path := filepath.Join(t.TempDir(), "access.log")
	line := `{"ts":1761200000,"logger":"http.log.access.s_aaaaaaaaaaaa","request":{"client_ip":"1.2.3.4","method":"GET","host":"a.com","uri":"/"},"status":200,"resp_headers":{"Content-Type":["text/html"]}}` + "\n"
	if err := os.WriteFile(path, []byte(line+line), 0o644); err != nil {
		t.Fatal(err)
	}
	tl := &Tailer{Path: path, Store: st, Access: true, OffsetKey: "access_offset",
		Country: func(string) string { return "TW" }}
	if err := tl.Once(ctx); err != nil {
		t.Fatal(err)
	}
	o, err := st.Overview(ctx, store.RequestFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if o.Requests != 2 || o.PV != 2 || o.UniqueIPs != 1 {
		t.Fatalf("overview = %+v", o)
	}
	top, _ := st.TopRequests(ctx, store.RequestFilter{}, store.DimCountry, 5)
	if len(top) != 1 || top[0].Key != "TW" {
		t.Fatalf("top = %+v", top)
	}
}
