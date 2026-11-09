package ratelimit

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"hostinginside/waf/engine/clientip"
	"hostinginside/waf/engine/events"
)

// TxHeader is the request header carrying the Coraza transaction ID; coraza-caddy
// reads it via its tx_id_req_header option.
const TxHeader = "X-Hi-Waf-Tx"

func init() {
	caddy.RegisterModule(RateLimit{})
	caddy.RegisterModule(BanAdmin{})
}

// RateLimit is the http.handlers.hi_ratelimit middleware. It bans client IPs
// that exceed the access, attack (WAF block) or error (4xx/5xx) limits. A nil
// limit is off.
type RateLimit struct {
	SiteID string `json:"site_id"`
	Access *Limit `json:"access,omitempty"`
	Attack *Limit `json:"attack,omitempty"`
	Error  *Limit `json:"error,omitempty"`

	state    *State
	acquired bool
	logger   *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (RateLimit) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hi_ratelimit",
		New: func() caddy.Module { return new(RateLimit) },
	}
}

// Provision takes a reference to the site's shared State.
func (rl *RateLimit) Provision(ctx caddy.Context) error {
	rl.logger = ctx.Logger()
	st, err := acquire(rl.SiteID)
	if err != nil {
		return err
	}
	rl.state, rl.acquired = st, true
	return nil
}

// Validate checks the config.
func (rl *RateLimit) Validate() error {
	if rl.SiteID == "" {
		return errors.New("site_id is required")
	}
	for _, l := range []struct {
		name string
		lim  *Limit
	}{{"access", rl.Access}, {"attack", rl.Attack}, {"error", rl.Error}} {
		if l.lim != nil && (l.lim.Requests <= 0 || l.lim.WindowSec <= 0 || l.lim.BanSec <= 0) {
			return fmt.Errorf("%s limit: requests, window_sec and ban_sec must all be > 0", l.name)
		}
	}
	return nil
}

// Cleanup releases the reference taken in Provision.
func (rl *RateLimit) Cleanup() error {
	if !rl.acquired {
		return nil
	}
	rl.acquired = false
	return release(rl.SiteID)
}

// ServeHTTP enforces bans, counts the request and then counts the outcome of
// the rest of the chain. next's error is always returned unchanged.
func (rl *RateLimit) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ip := Key(clientip.Get(r))
	now := time.Now()

	// Already banned: no event, to avoid a log line per blocked request.
	if until, banned := rl.state.BannedUntil(ip, now); banned {
		events.Tag(r, events.ActionRateLimit, "banned")
		return tooManyRequests(w, until, now)
	}
	if rl.Access != nil {
		if until, newly := rl.state.Record(KindAccess, ip, *rl.Access, now); newly {
			rl.emitBan(r, until, "access")
			events.Tag(r, events.ActionRateLimit, "access")
			return tooManyRequests(w, until, now)
		}
	}

	tx := rl.SiteID + "-" + randomHex8()
	r.Header.Set(TxHeader, tx)
	events.TagTx(r, tx)

	sw := &statusWriter{ResponseWriterWrapper: &caddyhttp.ResponseWriterWrapper{ResponseWriter: w}}
	err := next.ServeHTTP(sw, r)

	if ruleID, ok := isWAFInterruption(err); ok {
		e := events.FromRequest(r, events.TypeWAFBlock, rl.SiteID)
		e.RuleID, e.TxID = ruleID, tx
		events.Emit(rl.logger, e)
		events.Tag(r, events.ActionBlock, events.TypeWAFBlock)
		if rl.Attack != nil {
			if until, newly := rl.state.Record(KindAttack, ip, *rl.Attack, time.Now()); newly {
				rl.emitBan(r, until, "attack")
			}
		}
		return err
	}

	status := sw.status
	var he caddyhttp.HandlerError
	if errors.As(err, &he) && he.StatusCode != 0 {
		status = he.StatusCode
	}
	if status >= 400 && rl.Error != nil {
		if until, newly := rl.state.Record(KindError, ip, *rl.Error, time.Now()); newly {
			rl.emitBan(r, until, "error")
		}
	}
	return err
}

func (rl *RateLimit) emitBan(r *http.Request, until time.Time, limit string) {
	e := events.FromRequest(r, events.TypeRateLimitBan, rl.SiteID)
	e.Until = until
	e.Msg = limit
	events.Emit(rl.logger, e)
}

// tooManyRequests sets Retry-After (remaining ban, rounded up, at least 1 s)
// and returns a 429 handler error.
func tooManyRequests(w http.ResponseWriter, until, now time.Time) error {
	secs := int(math.Ceil(until.Sub(now).Seconds()))
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	return caddyhttp.Error(http.StatusTooManyRequests, errors.New("rate limited"))
}

func randomHex8() string {
	var b [8]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b[:])
}

// statusWriter records the final response status written by later handlers.
type statusWriter struct {
	*caddyhttp.ResponseWriterWrapper
	status int
}

func (sw *statusWriter) WriteHeader(code int) {
	if sw.status < 200 { // keep the first final (non-1xx) status
		sw.status = code
	}
	sw.ResponseWriterWrapper.WriteHeader(code)
}

// interruptionRe matches coraza-caddy's interruption error message: the
// released v2.6.x returns a bare "interruption triggered", newer main adds
// " by rule <id> (<action>)".
var interruptionRe = regexp.MustCompile(`^interruption triggered(?:$| by rule (\d+) )`)

// isWAFInterruption reports whether err is a coraza-caddy interruption and,
// if so, the rule ID that triggered it ("" when coraza-caddy doesn't say).
func isWAFInterruption(err error) (ruleID string, ok bool) {
	var he caddyhttp.HandlerError
	if err == nil || !errors.As(err, &he) || he.Err == nil {
		return "", false
	}
	m := interruptionRe.FindStringSubmatch(he.Err.Error())
	if m == nil {
		return "", false
	}
	return m[1], true
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*RateLimit)(nil)
	_ caddy.Validator             = (*RateLimit)(nil)
	_ caddy.CleanerUpper          = (*RateLimit)(nil)
	_ caddyhttp.MiddlewareHandler = (*RateLimit)(nil)
)
