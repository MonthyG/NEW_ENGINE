package store

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/site"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.ToSlash(filepath.Join(t.TempDir(), "test.db")))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestTxRollbackOnError(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	want := errors.New("x")
	err := s.Tx(ctx, func(tx *Tx) error {
		if err := tx.PutSite(SiteRecord{ID: "s_000000000001", Created: time.Now(), Updated: time.Now()}); err != nil {
			return err
		}
		return want
	})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	recs, err := s.ListSites(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no sites after rollback, got %d", len(recs))
	}
}

func TestTxRollbackOnPanic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	func() {
		defer func() {
			if recover() == nil {
				t.Error("expected re-panic")
			}
		}()
		_ = s.Tx(ctx, func(tx *Tx) error {
			_ = tx.PutSite(SiteRecord{ID: "s_000000000001", Created: time.Now(), Updated: time.Now()})
			panic("boom")
		})
	}()
	recs, err := s.ListSites(ctx)
	if err != nil || len(recs) != 0 {
		t.Fatalf("recs=%d err=%v, want empty", len(recs), err)
	}
}

func TestSiteRoundTripPreservesNull(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	doc := site.Doc{
		Domains:   []string{"example.com"},
		Upstreams: []string{"http://127.0.0.1:8080"},
		RateLimit: &site.RateLimitDoc{},
	}
	doc.RateLimit.Error = site.Optional[ratelimit.Limit]{Set: true, Null: true}
	now := time.Now().UTC().Truncate(time.Millisecond)
	err := s.Tx(ctx, func(tx *Tx) error {
		return tx.PutSite(SiteRecord{ID: "s_000000000001", Doc: doc, Created: now, Updated: now})
	})
	if err != nil {
		t.Fatal(err)
	}
	recs, err := s.ListSites(ctx)
	if err != nil || len(recs) != 1 {
		t.Fatalf("recs=%d err=%v", len(recs), err)
	}
	rl := recs[0].Doc.RateLimit
	if rl == nil || !rl.Error.Null || !rl.Error.Set {
		t.Fatalf("Error should be explicit null, got %+v", rl)
	}
	if rl.Attack.Set || rl.Access.Set {
		t.Fatalf("omitted limits must stay omitted, got %+v", rl)
	}
	if !recs[0].Created.Equal(now) || recs[0].Created.Location() != time.UTC {
		t.Fatalf("created = %v, want %v in UTC", recs[0].Created, now)
	}
}

func TestEventsFilterAndStats(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Millisecond)
	evs := []Event{
		{TS: base, SiteID: "a", Type: "waf_match", ClientIP: "1.1.1.1", RuleID: "942100"},
		{TS: base.Add(time.Second), SiteID: "a", Type: "waf_match", ClientIP: "1.1.1.1", RuleID: "942100"},
		{TS: base.Add(2 * time.Second), SiteID: "a", Type: "waf_match", ClientIP: "2.2.2.2", RuleID: "941100"},
		{TS: base.Add(3 * time.Second), SiteID: "b", Type: "ip_block", ClientIP: "3.3.3.3"},
	}
	if err := s.InsertEvents(ctx, evs); err != nil {
		t.Fatal(err)
	}
	got, err := s.QueryEvents(ctx, EventFilter{Type: "waf_match"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].RuleID != "941100" || got[2].TS.After(got[0].TS) {
		t.Fatalf("not newest first: %+v", got)
	}
	got, _ = s.QueryEvents(ctx, EventFilter{IP: "3.3.3.3"})
	if len(got) != 1 || got[0].Type != "ip_block" {
		t.Fatalf("ip filter: %+v", got)
	}
	got, _ = s.QueryEvents(ctx, EventFilter{Since: base.Add(2 * time.Second)})
	if len(got) != 2 {
		t.Fatalf("since filter len = %d, want 2", len(got))
	}
	got, _ = s.QueryEvents(ctx, EventFilter{Limit: 1})
	if len(got) != 1 {
		t.Fatalf("limit len = %d, want 1", len(got))
	}

	st, err := s.Stats(ctx, "", time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.ByType["waf_match"] != 3 || st.ByType["ip_block"] != 1 {
		t.Fatalf("ByType = %v", st.ByType)
	}
	if len(st.TopRules) != 2 || st.TopRules[0] != (Count{Key: "942100", N: 2}) {
		t.Fatalf("TopRules = %+v", st.TopRules)
	}
	if st.TopIPs[0] != (Count{Key: "1.1.1.1", N: 2}) {
		t.Fatalf("TopIPs = %+v", st.TopIPs)
	}
	st, _ = s.Stats(ctx, "b", time.Time{})
	if st.ByType["ip_block"] != 1 || len(st.TopRules) != 0 {
		t.Fatalf("site-scoped stats = %+v", st)
	}
}

func TestDeleteSiteRemovesCert(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id := "s_000000000001"
	now := time.Now()
	err := s.Tx(ctx, func(tx *Tx) error {
		if err := tx.PutSite(SiteRecord{ID: id, Created: now, Updated: now}); err != nil {
			return err
		}
		return tx.PutCert(id, site.Cert{CertPEM: "c", KeyPEM: "k"})
	})
	if err != nil {
		t.Fatal(err)
	}
	cs, _ := s.Certs(ctx)
	if cs[id].CertPEM != "c" {
		t.Fatalf("cert missing: %v", cs)
	}
	var existed, again bool
	err = s.Tx(ctx, func(tx *Tx) error {
		var err error
		if existed, err = tx.DeleteSite(id); err != nil {
			return err
		}
		again, err = tx.DeleteSite(id)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if !existed || again {
		t.Fatalf("existed=%v again=%v, want true,false", existed, again)
	}
	cs, _ = s.Certs(ctx)
	if len(cs) != 0 {
		t.Fatalf("cert should be gone: %v", cs)
	}
}

func TestSettings(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if _, ok, err := s.Setting(ctx, "k"); err != nil || ok {
		t.Fatalf("ok=%v err=%v, want missing", ok, err)
	}
	if err := s.SetSetting(ctx, "k", "v1"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetSetting(ctx, "k", "v2"); err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := s.Setting(ctx, "k"); !ok || v != "v2" {
		t.Fatalf("v=%q ok=%v", v, ok)
	}
}
