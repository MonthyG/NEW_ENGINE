package events_test

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"hostinginside/waf/engine/events"
)

func TestEmitOmitsEmptyFields(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	events.Emit(zap.New(core), events.Event{Type: events.TypeIPBlock, SiteID: "s_aaaaaaaaaaaa", ClientIP: "1.2.3.4"})
	e := logs.All()[0]
	assert.Equal(t, "hi_event", e.Message)
	m := e.ContextMap()
	assert.Equal(t, "ip_block", m["event"])
	assert.Equal(t, "1.2.3.4", m["client_ip"])
	_, has := m["rule_id"]
	assert.False(t, has)
	_, has = m["until"]
	assert.False(t, has)
}

func TestEmitFormatsUntilAsRFC3339(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	until := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	events.Emit(zap.New(core), events.Event{Type: events.TypeRateLimitBan, Until: until, RuleID: "942100", Msg: "x"})
	m := logs.All()[0].ContextMap()
	assert.Equal(t, "2026-10-23T12:00:00Z", m["until"])
	assert.Equal(t, "942100", m["rule_id"])
	assert.Equal(t, "x", m["detail"])
	_, has := m["msg"]
	assert.False(t, has)
	assert.Equal(t, "hi_event", logs.All()[0].Message)
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest("POST", "/a?b=1", nil)
	r.Host = "example.com"
	r.RemoteAddr = "198.51.100.9:5555"
	e := events.FromRequest(r, events.TypeWAFBlock, "s_aaaaaaaaaaaa")
	assert.Equal(t, events.Event{
		Type: "waf_block", SiteID: "s_aaaaaaaaaaaa", ClientIP: "198.51.100.9",
		Host: "example.com", Method: "POST", URI: "/a?b=1",
	}, e)
}
