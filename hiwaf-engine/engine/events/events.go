// Package events defines the structured security events the engine logs.
package events

import (
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"hostinginside/waf/engine/clientip"
)

// LogMessage is the exact log message of every event line.
const LogMessage = "hi_event"

// Event types.
const (
	TypeWAFBlock        = "waf_block"
	TypeWAFMatch        = "waf_match"
	TypeRateLimitBan    = "rate_limit_ban"
	TypeIPBlock         = "ip_block"
	TypeGeoBlock        = "geo_block"
	TypeRuleBlock       = "rule_block"
	TypeAllowedByRule   = "allowed_by_rule"
	TypeChallengePassed = "challenge_passed"
	TypeChallengeFailed = "challenge_failed"
	TypeAuthPassed      = "auth_passed"
	TypeAuthFailed      = "auth_failed"
	TypeWaitQueued      = "wait_queued"
)

// Access-log actions recorded by Tag.
const (
	ActionDeny      = "deny"  // hi_access block (IP, geo, rule)
	ActionAllow     = "allow" // hi_access allowlist or allow rule
	ActionBlock     = "block" // WAF interruption
	ActionRateLimit = "rate_limit"
	ActionChallenge = "challenge" // challenge page served or failed
	ActionAuth      = "auth"      // auth login page served or failed
	ActionWait      = "wait"      // waiting-room page served
)

// Tag records what the WAF did with r in Caddy's access log entry for it, as
// the fields hi_action and hi_type. It is a no-op outside a Caddy server.
func Tag(r *http.Request, action, typ string) {
	extra, ok := r.Context().Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields)
	if !ok {
		return
	}
	extra.Set(zap.String("hi_action", action))
	if typ != "" {
		extra.Set(zap.String("hi_type", typ))
	}
}

// TagTx records the Coraza transaction ID in the access log entry.
func TagTx(r *http.Request, tx string) {
	if extra, ok := r.Context().Value(caddyhttp.ExtraLogFieldsCtxKey).(*caddyhttp.ExtraLogFields); ok {
		extra.Set(zap.String("hi_tx", tx))
	}
}

// Event is one security event. Empty fields are omitted when logged.
type Event struct {
	Type     string
	SiteID   string
	ClientIP string
	Host     string
	Method   string
	URI      string
	RuleID   string
	Msg      string
	TxID     string
	Until    time.Time
}

// Emit logs e at Info level with message LogMessage.
func Emit(l *zap.Logger, e Event) {
	fields := make([]zap.Field, 0, 9)
	add := func(key, val string) {
		if val != "" {
			fields = append(fields, zap.String(key, val))
		}
	}
	add("event", e.Type)
	add("site_id", e.SiteID)
	add("client_ip", e.ClientIP)
	add("host", e.Host)
	add("method", e.Method)
	add("uri", e.URI)
	add("rule_id", e.RuleID)
	add("detail", e.Msg)
	add("tx_id", e.TxID)
	if !e.Until.IsZero() {
		fields = append(fields, zap.String("until", e.Until.UTC().Format(time.RFC3339)))
	}
	l.Info(LogMessage, fields...)
}

// FromRequest builds an Event of type typ for site siteID from r.
func FromRequest(r *http.Request, typ, siteID string) Event {
	return Event{
		Type:     typ,
		SiteID:   siteID,
		ClientIP: clientip.Get(r),
		Host:     r.Host,
		Method:   r.Method,
		URI:      r.URL.RequestURI(),
	}
}
