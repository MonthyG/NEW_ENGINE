package site

import (
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/manager/crsplugins"
)

// ValidationError names the JSON path of the offending field.
type ValidationError struct{ Field, Msg string }

func (e *ValidationError) Error() string { return e.Field + ": " + e.Msg }

func verr(field, format string, args ...any) error {
	return &ValidationError{Field: field, Msg: fmt.Sprintf(format, args...)}
}

// Validate checks d and returns the first problem as a *ValidationError.
func Validate(d Doc, geoEnabled bool) error {
	if utf8.RuneCountInString(d.Name) > 64 {
		return verr("name", "must be at most 64 characters")
	}
	if utf8.RuneCountInString(d.Description) > 500 {
		return verr("description", "must be at most 500 characters")
	}
	if d.Project != "" && !ValidProject(d.Project) {
		return verr("project", "must be 1-64 letters, digits, - or _")
	}
	tlsOff := d.TLS != nil && d.TLS.Mode == "off"
	if len(d.Domains) == 0 {
		return verr("domains", "at least one domain is required")
	}
	for i, dom := range d.Domains {
		dom = strings.ToLower(strings.TrimSpace(dom))
		if dom == "*" {
			if !tlsOff {
				return verr(fmt.Sprintf("domains[%d]", i), "the match-all domain * needs tls.mode off")
			}
			continue
		}
		if !validHostname(dom, true) {
			return verr(fmt.Sprintf("domains[%d]", i), "invalid hostname %q", dom)
		}
	}
	switch d.Type {
	case "", "proxy":
		if err := validateUpstreams(d.Upstreams); err != nil {
			return err
		}
		switch d.LBPolicy {
		case "", "round_robin", "ip_hash", "least_conn":
		default:
			return verr("lb_policy", "must be round_robin, ip_hash or least_conn, got %q", d.LBPolicy)
		}
	case "static", "redirect":
		if len(d.Upstreams) > 0 {
			return verr("upstreams", "only proxy sites have upstreams")
		}
	default:
		return verr("type", "must be proxy, static or redirect, got %q", d.Type)
	}
	if d.Type == "redirect" {
		if err := validateRedirect(d.Redirect); err != nil {
			return err
		}
	} else if d.Redirect != nil {
		return verr("redirect", "only redirect sites have a redirect")
	}
	if err := validatePorts(d.Ports, tlsOff); err != nil {
		return err
	}
	if d.TLS != nil {
		switch d.TLS.Mode {
		case "", "auto", "uploaded", "off":
		default:
			return verr("tls.mode", "must be auto, uploaded or off, got %q", d.TLS.Mode)
		}
		if d.TLS.CertID != "" {
			if d.TLS.Mode != "uploaded" {
				return verr("tls.cert_id", "needs tls.mode uploaded")
			}
			if !objectID("c", d.TLS.CertID) {
				return verr("tls.cert_id", "invalid certificate ID %q", d.TLS.CertID)
			}
		}
	}
	if err := validateAuth(d.Auth); err != nil {
		return err
	}
	if wr := d.WaitingRoom; wr != nil {
		if wr.Enabled && wr.MaxActive < 1 {
			return verr("waiting_room.max_active", "must be at least 1")
		}
		if wr.MaxActive < 0 || wr.SessionTTLSec < 0 {
			return verr("waiting_room", "values must not be negative")
		}
	}
	if w := d.WAF; w != nil {
		switch w.Mode {
		case "", "block", "detect", "off":
		default:
			return verr("waf.mode", "must be block, detect or off, got %q", w.Mode)
		}
		if w.Paranoia != 0 && (w.Paranoia < 1 || w.Paranoia > 4) {
			return verr("waf.paranoia", "must be between 1 and 4, got %d", w.Paranoia)
		}
		if w.AnomalyThreshold < 0 {
			return verr("waf.anomaly_threshold", "must be at least 1, got %d", w.AnomalyThreshold)
		}
		keys := make([]string, 0, len(w.Protections))
		for k := range w.Protections {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if !knownProtection(k) {
				return verr("waf.protections."+k, "unknown protection")
			}
		}
		seen := map[string]bool{}
		for i, k := range w.Apps {
			if !crsplugins.Known(k) || seen[k] {
				return verr(fmt.Sprintf("waf.apps[%d]", i), "must be one of %s, once each; got %q", strings.Join(crsplugins.Keys(), ", "), k)
			}
			seen[k] = true
		}
	}
	if err := validateExclusions(d.Exclusions); err != nil {
		return err
	}
	if rl := d.RateLimit; rl != nil {
		for _, l := range []struct {
			name string
			opt  Optional[ratelimit.Limit]
		}{{"access", rl.Access}, {"attack", rl.Attack}, {"error", rl.Error}} {
			if !l.opt.Set || l.opt.Null {
				continue
			}
			v := l.opt.Value
			for _, f := range []struct {
				name string
				v    int
			}{{"requests", v.Requests}, {"window_sec", v.WindowSec}, {"ban_sec", v.BanSec}} {
				if f.v <= 0 {
					return verr("rate_limit."+l.name+"."+f.name, "must be greater than 0, got %d", f.v)
				}
			}
		}
	}
	if a := d.Access; a != nil {
		if err := validateAccess(a, geoEnabled); err != nil {
			return err
		}
	}
	if c := d.BotChallenge; c != nil && c.Difficulty != 0 && (c.Difficulty < 1 || c.Difficulty > 6) {
		return verr("bot_challenge.difficulty", "must be 0 (default) or between 1 and 6, got %d", c.Difficulty)
	}
	return nil
}

func knownProtection(k string) bool {
	for _, p := range Protections {
		if p.Key == k {
			return true
		}
	}
	return false
}

// objectID reports whether id is prefix + "_" + 12 lowercase hex characters.
func objectID(prefix, id string) bool {
	rest, ok := strings.CutPrefix(id, prefix+"_")
	if !ok || len(rest) != 12 {
		return false
	}
	for i := 0; i < len(rest); i++ {
		if c := rest[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validateRedirect(rd *RedirectDoc) error {
	if rd == nil || rd.URL == "" {
		return verr("redirect.url", "is required for redirect sites")
	}
	u, err := url.Parse(rd.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return verr("redirect.url", "must be an absolute http(s) URL, got %q", rd.URL)
	}
	if strings.ContainsAny(rd.URL, "{}") {
		return verr("redirect.url", "must not contain braces")
	}
	switch rd.Code {
	case 0, 301, 302, 307, 308:
	default:
		return verr("redirect.code", "must be 301, 302, 307 or 308, got %d", rd.Code)
	}
	return nil
}

func validatePorts(ports []PortDoc, tlsOff bool) error {
	seen := map[int]bool{}
	for i, p := range ports {
		field := fmt.Sprintf("ports[%d]", i)
		if p.Port < 1 || p.Port > 65535 {
			return verr(field+".port", "must be between 1 and 65535, got %d", p.Port)
		}
		if seen[p.Port] {
			return verr(field+".port", "port %d is listed twice", p.Port)
		}
		seen[p.Port] = true
		if p.HTTPS && tlsOff {
			return verr(field+".https", "an HTTPS port needs TLS (tls.mode auto or uploaded)")
		}
	}
	if len(ports) > 0 && !tlsOff {
		hasTLS := false
		for _, p := range ports {
			hasTLS = hasTLS || p.HTTPS
		}
		if !hasTLS {
			return verr("ports", "with TLS on, at least one port must be HTTPS (or set tls.mode off)")
		}
	}
	return nil
}

func validateAuth(a *AuthDoc) error {
	if a == nil {
		return nil
	}
	if a.Enabled && len(a.Users) == 0 {
		return verr("auth.users", "at least one user is required when auth is enabled")
	}
	if a.SessionTTLSec < 0 {
		return verr("auth.session_ttl_sec", "must not be negative")
	}
	seen := map[string]bool{}
	for i, u := range a.Users {
		field := fmt.Sprintf("auth.users[%d]", i)
		if u.Username == "" || len(u.Username) > 64 || strings.ContainsAny(u.Username, "|. \t") {
			return verr(field+".username", "must be 1-64 characters without spaces, dots or |")
		}
		if seen[u.Username] {
			return verr(field+".username", "duplicate username %q", u.Username)
		}
		seen[u.Username] = true
		switch {
		case u.Password != "":
			if n := utf8.RuneCountInString(u.Password); n < 6 || len(u.Password) > 72 {
				return verr(field+".password", "must be 6-72 bytes")
			}
		case u.PasswordHash == "":
			return verr(field+".password", "is required")
		}
	}
	return nil
}

func validateAccess(a *AccessDoc, geoEnabled bool) error {
	for _, l := range []struct {
		field string
		ids   []string
	}{{"access.allow_groups", a.AllowGroups}, {"access.block_groups", a.BlockGroups}} {
		for _, id := range l.ids {
			if !objectID("g", id) {
				return verr(l.field, "invalid IP group ID %q", id)
			}
		}
	}
	for _, l := range []struct {
		field string
		ips   []string
	}{{"access.allow_ips", a.AllowIPs}, {"access.block_ips", a.BlockIPs}} {
		if _, err := access.ParseIPSet(l.ips); err != nil {
			return verr(l.field, "%s", err.Error())
		}
	}
	if f := a.BlockIPsFile; f != "" {
		if strings.TrimSpace(f) == "" || strings.ContainsAny(f, `/\`) || strings.Contains(f, "..") {
			return verr("access.block_ips_file", "must be a plain file name in the feeds directory, got %q", f)
		}
	}
	for _, l := range []struct {
		field string
		cc    []string
	}{{"access.allow_countries", a.AllowCountries}, {"access.block_countries", a.BlockCountries}} {
		if err := validateCountries(l.field, l.cc, geoEnabled); err != nil {
			return err
		}
	}
	for i, r := range a.Rules {
		base := fmt.Sprintf("access.rules[%d]", i)
		if err := validateCountries(base+".match.country", r.Match.Country, geoEnabled); err != nil {
			return err
		}
		if err := r.Validate(); err != nil {
			prefix, msg, ok := strings.Cut(err.Error(), ": ")
			if !ok {
				return verr(base, "%s", err.Error())
			}
			if prefix == "action" || prefix == "match" {
				return verr(base, "%s", msg)
			}
			return verr(base+"."+prefix, "%s", msg)
		}
	}
	return nil
}

func validateCountries(field string, cc []string, geoEnabled bool) error {
	if len(cc) == 0 {
		return nil
	}
	if !geoEnabled {
		return verr(field, "country rules need the GeoIP database, which is not configured")
	}
	for _, c := range cc {
		c = strings.TrimSpace(c)
		if len(c) != 2 || !isLetter(c[0]) || !isLetter(c[1]) {
			return verr(field, "invalid country code %q (want two letters)", c)
		}
	}
	return nil
}

func isLetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// validHostname accepts lowercase labels of letters, digits and hyphens (1-63
// chars, not starting or ending with a hyphen), total up to 253, with an
// optional leading "*." when wildcard is true. IP literals are accepted.
func validHostname(h string, wildcard bool) bool {
	if net.ParseIP(h) != nil {
		return true
	}
	if wildcard {
		h = strings.TrimPrefix(h, "*.")
	}
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

func validateUpstreams(ups []string) error {
	if len(ups) == 0 {
		return verr("upstreams", "at least one upstream is required")
	}
	scheme := ""
	for i, u := range ups {
		field := fmt.Sprintf("upstreams[%d]", i)
		s, rest := "http", u
		if strings.HasPrefix(u, "http://") {
			rest = strings.TrimPrefix(u, "http://")
		} else if strings.HasPrefix(u, "https://") {
			s, rest = "https", strings.TrimPrefix(u, "https://")
		}
		host, port, err := net.SplitHostPort(rest)
		if err != nil || host == "" {
			return verr(field, "must be host:port or http(s)://host:port, got %q", u)
		}
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return verr(field, "invalid port in %q", u)
		}
		if !validHostname(strings.ToLower(host), false) {
			return verr(field, "invalid host in %q", u)
		}
		if scheme == "" {
			scheme = s
		} else if s != scheme {
			return verr(field, "all upstreams must use the same scheme")
		}
	}
	return nil
}

// ValidateAll checks cross-site constraints: no domain may belong to two sites.
func ValidateAll(sites []Resolved) error {
	owner := map[string]string{}
	for _, s := range sites {
		for _, d := range s.Domains {
			d = strings.ToLower(d)
			if o, ok := owner[d]; ok && o != s.ID {
				return verr("domains", "domain %q is already used by site %s", d, o)
			}
			owner[d] = s.ID
		}
	}
	return nil
}
