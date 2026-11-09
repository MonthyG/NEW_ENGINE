// Package site is the manager-side data model: the customer's simple site
// document, its defaults, and validation.
package site

import (
	"bytes"
	"encoding/json"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
)

// Optional distinguishes an omitted JSON field (neither Set nor Null) from an
// explicit null (Set and Null) and from a value (Set).
type Optional[T any] struct {
	Set, Null bool
	Value     T
}

// UnmarshalJSON records presence, and whether the literal was null.
func (o *Optional[T]) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		o.Null = true
		var zero T
		o.Value = zero
		return nil
	}
	o.Null = false
	return json.Unmarshal(b, &o.Value)
}

// MarshalJSON emits null when Null, the value otherwise. Fields tagged
// omitzero drop an unset Optional entirely.
func (o Optional[T]) MarshalJSON() ([]byte, error) {
	if o.Null || !o.Set {
		return []byte("null"), nil
	}
	return json.Marshal(o.Value)
}

// Resolve returns nil when explicitly null, the value when set, else def.
func (o Optional[T]) Resolve(def *T) *T {
	if o.Null {
		return nil
	}
	if o.Set {
		v := o.Value
		return &v
	}
	return def
}

// Doc is the customer-facing site document.
type Doc struct {
	Name         string          `json:"name,omitempty"`
	Description  string          `json:"description,omitempty"`
	Project      string          `json:"project,omitempty"` // owning project (an OpenStack project ID); empty = the operator's
	Type         string          `json:"type,omitempty"`    // proxy (default) | static | redirect
	Domains      []string        `json:"domains"`
	Ports        []PortDoc       `json:"ports,omitempty"`
	Upstreams    []string        `json:"upstreams,omitempty"`
	LBPolicy     string          `json:"lb_policy,omitempty"` // round_robin (default) | ip_hash | least_conn
	Redirect     *RedirectDoc    `json:"redirect,omitempty"`
	Advanced     *AdvancedDoc    `json:"advanced,omitempty"`
	TLS          *TLSDoc         `json:"tls,omitempty"`
	WAF          *WAFDoc         `json:"waf,omitempty"`
	RateLimit    *RateLimitDoc   `json:"rate_limit,omitempty"`
	Access       *AccessDoc      `json:"access,omitempty"`
	BotChallenge *ChallengeDoc   `json:"bot_challenge,omitempty"`
	Auth         *AuthDoc        `json:"auth,omitempty"`
	WaitingRoom  *WaitingRoomDoc `json:"waiting_room,omitempty"`
	BlockPage    *BlockPageDoc   `json:"block_page,omitempty"`
	Exclusions   []Exclusion     `json:"exclusions,omitempty"`
}

// PortDoc is one listening port. Without ports a site listens on the global
// HTTP port and, unless TLS is off, the global HTTPS port.
type PortDoc struct {
	Port  int  `json:"port"`
	HTTPS bool `json:"https"`
}

// RedirectDoc configures a redirect site.
type RedirectDoc struct {
	URL          string `json:"url"`
	Code         int    `json:"code,omitempty"` // 301 | 302 (default) | 307 | 308
	PreservePath bool   `json:"preserve_path,omitempty"`
}

// AdvancedDoc holds the "Advanced" switches. Pointers default to true.
type AdvancedDoc struct {
	HSTS         bool  `json:"hsts,omitempty"`
	Gzip         bool  `json:"gzip,omitempty"`
	HTTPRedirect *bool `json:"http_redirect,omitempty"` // HTTP -> HTTPS, default true
	KeepHost     *bool `json:"keep_host,omitempty"`     // pass the client Host upstream, default true
}

// AuthDoc configures the password gate. On input a user carries a plain
// Password, which the API replaces with PasswordHash before storing.
type AuthDoc struct {
	Enabled       bool          `json:"enabled"`
	Users         []AuthUserDoc `json:"users,omitempty"`
	SessionTTLSec int           `json:"session_ttl_sec,omitempty"`
}

// AuthUserDoc is one password-gate user.
type AuthUserDoc struct {
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// WaitingRoomDoc configures the waiting room.
type WaitingRoomDoc struct {
	Enabled       bool `json:"enabled"`
	MaxActive     int  `json:"max_active,omitempty"`
	SessionTTLSec int  `json:"session_ttl_sec,omitempty"`
}

// TLSDoc configures TLS.
type TLSDoc struct {
	Mode   string `json:"mode,omitempty"`    // auto | uploaded | off
	CertID string `json:"cert_id,omitempty"` // a global certificate, for mode uploaded
}

// WAFDoc configures the WAF.
type WAFDoc struct {
	Mode             string          `json:"mode,omitempty"` // block | detect | off
	Paranoia         int             `json:"paranoia,omitempty"`
	AnomalyThreshold int             `json:"anomaly_threshold,omitempty"`
	Protections      map[string]bool `json:"protections,omitempty"`
	Apps             []string        `json:"apps,omitempty"` // app profiles: crsplugins.Catalog keys
}

// RateLimitDoc holds the three limits; each distinguishes omitted from null.
type RateLimitDoc struct {
	Access Optional[ratelimit.Limit] `json:"access,omitzero"`
	Attack Optional[ratelimit.Limit] `json:"attack,omitzero"`
	Error  Optional[ratelimit.Limit] `json:"error,omitzero"`
}

// AccessDoc holds IP/country lists and custom rules.
type AccessDoc struct {
	AllowIPs       []string      `json:"allow_ips,omitempty"`
	BlockIPs       []string      `json:"block_ips,omitempty"`
	AllowCountries []string      `json:"allow_countries,omitempty"`
	BlockCountries []string      `json:"block_countries,omitempty"`
	BlockIPsFile   string        `json:"block_ips_file,omitempty"`
	AllowGroups    []string      `json:"allow_groups,omitempty"` // IP group IDs
	BlockGroups    []string      `json:"block_groups,omitempty"`
	Rules          []access.Rule `json:"rules,omitempty"`
}

// ChallengeDoc configures the bot challenge.
type ChallengeDoc struct {
	Enabled    bool `json:"enabled"`
	Difficulty int  `json:"difficulty,omitempty"` // 0 = default (4), else 1-6
}

// BlockPageDoc customises the block page.
type BlockPageDoc struct {
	Title   string `json:"title,omitempty"`
	Message string `json:"message,omitempty"`
}

// Cert is an uploaded certificate and key in PEM form.
type Cert struct {
	CertPEM string
	KeyPEM  string
}
