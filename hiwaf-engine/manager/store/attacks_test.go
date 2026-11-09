package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAttacksQualifyAndJoin(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "a.db"))
	require.NoError(t, err)
	defer s.Close()
	base := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	match := func(tx, rule, cat string, sev int, off time.Duration) Event {
		return Event{TS: base.Add(off), SiteID: "s_a", Type: "waf_match", ClientIP: "1.1.1.1",
			URI: "/?id=1", RuleID: rule, Msg: "m" + rule, TxID: tx, Severity: sev, Category: cat, Data: "d" + rule}
	}
	require.NoError(t, s.InsertEvents(ctx, []Event{
		match("tx1", "942100", "sqli", 2, 0),
		match("tx1", "949110", "score", 2, 0),
		match("tx2", "920350", "protocol", 4, time.Second), // warning only, not blocked: hidden
		match("tx3", "920350", "protocol", 4, 2*time.Second),
		{TS: base.Add(2 * time.Second), SiteID: "s_a", Type: "waf_block", ClientIP: "1.1.1.1", TxID: "tx3"},
		{TS: base.Add(3 * time.Second), SiteID: "s_b", Type: "waf_match", ClientIP: "2.2.2.2", TxID: "tx4",
			RuleID: "941100", Category: "xss", Severity: 2},
	}))
	require.NoError(t, s.InsertRequests(ctx, []Request{{TS: base, SiteID: "s_a", ClientIP: "1.1.1.1",
		Country: "TW", Method: "GET", Host: "a.com", URI: "/?id=1", Status: 403, Action: "block", TxID: "tx1"}}))

	got, total, err := s.Attacks(ctx, AttackFilter{})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	require.Len(t, got, 3)
	assert.Equal(t, "tx4", got[0].TxID)
	assert.Equal(t, "tx3", got[1].TxID)
	assert.True(t, got[1].Blocked, "waf_block event marks it blocked")
	a := got[2]
	assert.Equal(t, "tx1", a.TxID)
	assert.Equal(t, "942100", a.RuleID, "most severe non-score match")
	assert.Equal(t, "d942100", a.Data)
	assert.Equal(t, []string{"sqli"}, a.Categories)
	assert.Equal(t, "a.com", a.Host)
	assert.Equal(t, "TW", a.Country)
	assert.True(t, a.Blocked)

	got, total, err = s.Attacks(ctx, AttackFilter{Category: "xss"})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Equal(t, "tx4", got[0].TxID)

	groups, total, err := s.AttackGroups(ctx, AttackFilter{SiteID: "s_a"})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Equal(t, 2, groups[0].Count)

	counts, err := s.AttackCounts(ctx, "", time.Time{})
	require.NoError(t, err)
	assert.ElementsMatch(t, []Count{{Key: "sqli", N: 1}, {Key: "protocol", N: 1}, {Key: "xss", N: 1}}, counts)
}

func TestRuleHitsAndLatency(t *testing.T) {
	ctx := context.Background()
	s, err := Open(filepath.Join(t.TempDir(), "r.db"))
	require.NoError(t, err)
	defer s.Close()
	base := time.Date(2026, 10, 25, 10, 0, 0, 0, time.UTC)
	ev := func(rule, cat, tx string) Event {
		return Event{TS: base, SiteID: "s_a", Type: "waf_match", ClientIP: "1.1.1.1", RuleID: rule, Msg: "m" + rule, Category: cat, TxID: tx}
	}
	// t1 is stopped by a block event, t2 by its request's action, t3 only watched
	require.NoError(t, s.InsertEvents(ctx, []Event{ev("942100", "sqli", "t1"), ev("942100", "sqli", "t3"), ev("941100", "xss", "t2"),
		ev("949110", "score", "t1"), {TS: base, SiteID: "s_a", Type: "waf_block", ClientIP: "1.1.1.1", TxID: "t1"}}))
	require.NoError(t, s.InsertRequests(ctx, []Request{{TS: base.Add(-time.Hour), SiteID: "s_a", Action: "block", TxID: "t2"}}))
	hits, err := s.RuleHits(ctx, "", time.Time{}, 8)
	require.NoError(t, err)
	assert.Equal(t, []RuleHit{{"942100", "m942100", "sqli", 2, 1}, {"941100", "m941100", "xss", 1, 1}}, hits)

	p, err := s.LatencyP95(ctx, RequestFilter{Since: base})
	require.NoError(t, err)
	assert.Zero(t, p)
	var reqs []Request
	for i := 1; i <= 100; i++ {
		reqs = append(reqs, Request{TS: base, SiteID: "s_a", DurMS: float64(i)})
	}
	require.NoError(t, s.InsertRequests(ctx, reqs))
	p, err = s.LatencyP95(ctx, RequestFilter{Since: base})
	require.NoError(t, err)
	assert.Equal(t, 95.0, p)
	one := []Request{{TS: base, SiteID: "s_b", DurMS: 7}} // a single request is its own p95
	require.NoError(t, s.InsertRequests(ctx, one))
	p, err = s.LatencyP95(ctx, RequestFilter{SiteID: "s_b"})
	require.NoError(t, err)
	assert.Equal(t, 7.0, p)
}
