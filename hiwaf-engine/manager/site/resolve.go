package site

import (
	"crypto/rand"
	"encoding/hex"
	"strings"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
)

// Resolved is a site with every default applied.
type Resolved struct {
	ID, Name            string
	Description, Type   string
	Domains, Upstreams  []string
	Ports               []PortDoc // empty = the global HTTP (+ HTTPS) ports
	LBPolicy            string
	RedirectURL         string
	RedirectCode        int
	PreservePath        bool
	HSTS, Gzip          bool
	HTTPRedirect        bool
	KeepHost            bool
	CertID              string
	AllowGroups         []string
	BlockGroups         []string
	AuthEnabled         bool
	AuthUsers           []AuthUserDoc
	AuthTTL             int
	WaitEnabled         bool
	WaitMax, WaitTTL    int
	TLSMode, WAFMode    string
	Paranoia            int
	AnomalyThreshold    int
	Protections         map[string]bool
	Apps                []string
	Access, Attack      *ratelimit.Limit
	Error               *ratelimit.Limit
	AllowIPs, BlockIPs  []string
	AllowCountries      []string
	BlockCountries      []string
	BlockIPsFile        string
	Rules               []access.Rule
	Challenge           bool
	ChallengeDifficulty int
	BlockTitle          string
	BlockMessage        string
	Exclusions          []Exclusion
}

const (
	defaultBlockTitle   = "Request blocked"
	defaultBlockMessage = "Your request was blocked by the web application firewall."
)

// Resolve applies defaults to d. Omitted fields get defaults, explicit null
// rate limits turn the limit off, and protections merge over the catalog.
func Resolve(id string, d Doc) Resolved {
	r := Resolved{
		ID:                  id,
		Name:                d.Name,
		Description:         d.Description,
		Type:                "proxy",
		LBPolicy:            "round_robin",
		HTTPRedirect:        true,
		KeepHost:            true,
		TLSMode:             "auto",
		WAFMode:             "block",
		Paranoia:            1,
		AnomalyThreshold:    5,
		Protections:         map[string]bool{},
		ChallengeDifficulty: 4,
		BlockTitle:          defaultBlockTitle,
		BlockMessage:        defaultBlockMessage,
	}
	for _, dom := range d.Domains {
		r.Domains = append(r.Domains, strings.ToLower(strings.TrimSpace(dom)))
	}
	r.Upstreams = append([]string(nil), d.Upstreams...)
	r.Exclusions = append([]Exclusion(nil), d.Exclusions...)
	r.Ports = append([]PortDoc(nil), d.Ports...)
	if d.Type != "" {
		r.Type = d.Type
	}
	if d.LBPolicy != "" {
		r.LBPolicy = d.LBPolicy
	}
	if rd := d.Redirect; rd != nil {
		r.RedirectURL, r.RedirectCode, r.PreservePath = rd.URL, rd.Code, rd.PreservePath
		if r.RedirectCode == 0 {
			r.RedirectCode = 302
		}
	}
	if adv := d.Advanced; adv != nil {
		r.HSTS, r.Gzip = adv.HSTS, adv.Gzip
		if adv.HTTPRedirect != nil {
			r.HTTPRedirect = *adv.HTTPRedirect
		}
		if adv.KeepHost != nil {
			r.KeepHost = *adv.KeepHost
		}
	}
	if au := d.Auth; au != nil {
		r.AuthEnabled = au.Enabled
		r.AuthUsers = append([]AuthUserDoc(nil), au.Users...)
		r.AuthTTL = au.SessionTTLSec
	}
	if wr := d.WaitingRoom; wr != nil {
		r.WaitEnabled, r.WaitMax, r.WaitTTL = wr.Enabled, wr.MaxActive, wr.SessionTTLSec
	}
	for _, p := range Protections {
		r.Protections[p.Key] = p.Default
	}
	if d.TLS != nil {
		if d.TLS.Mode != "" {
			r.TLSMode = d.TLS.Mode
		}
		r.CertID = d.TLS.CertID
	}
	if w := d.WAF; w != nil {
		if w.Mode != "" {
			r.WAFMode = w.Mode
		}
		if w.Paranoia != 0 {
			r.Paranoia = w.Paranoia
		}
		if w.AnomalyThreshold != 0 {
			r.AnomalyThreshold = w.AnomalyThreshold
		}
		r.Apps = append([]string(nil), w.Apps...)
		for k, v := range w.Protections {
			if _, known := r.Protections[k]; known {
				r.Protections[k] = v
			}
		}
	}
	var rl RateLimitDoc
	if d.RateLimit != nil {
		rl = *d.RateLimit
	}
	r.Access = rl.Access.Resolve(nil)
	r.Attack = rl.Attack.Resolve(&ratelimit.Limit{Requests: 10, WindowSec: 60, BanSec: 1800})
	r.Error = rl.Error.Resolve(&ratelimit.Limit{Requests: 50, WindowSec: 60, BanSec: 600})
	if a := d.Access; a != nil {
		r.AllowIPs = append([]string(nil), a.AllowIPs...)
		r.BlockIPs = append([]string(nil), a.BlockIPs...)
		r.AllowCountries = upperAll(a.AllowCountries)
		r.BlockCountries = upperAll(a.BlockCountries)
		r.BlockIPsFile = a.BlockIPsFile
		r.AllowGroups = append([]string(nil), a.AllowGroups...)
		r.BlockGroups = append([]string(nil), a.BlockGroups...)
		r.Rules = append([]access.Rule(nil), a.Rules...)
	}
	if c := d.BotChallenge; c != nil {
		r.Challenge = c.Enabled
		if c.Difficulty != 0 {
			r.ChallengeDifficulty = c.Difficulty
		}
	}
	if b := d.BlockPage; b != nil {
		if b.Title != "" {
			r.BlockTitle = b.Title
		}
		if b.Message != "" {
			r.BlockMessage = b.Message
		}
	}
	return r
}

func upperAll(in []string) []string {
	var out []string
	for _, s := range in {
		out = append(out, strings.ToUpper(strings.TrimSpace(s)))
	}
	return out
}

// NewID returns "s_" plus 12 lowercase hex characters.
func NewID() string {
	var b [6]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24
	return "s_" + hex.EncodeToString(b[:])
}
