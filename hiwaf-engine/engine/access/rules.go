package access

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"path"
	"regexp"
	"strings"
)

// Rule is a custom access rule. Conditions in Match are ANDed.
type Rule struct {
	Name   string `json:"name,omitempty"` // labels the rule in events
	Action string `json:"action"`         // "block" or "allow"
	Match  Match  `json:"match"`
}

// Match holds the conditions of a rule; empty conditions are ignored.
type Match struct {
	IP         []string `json:"ip,omitempty"`
	NotIP      []string `json:"not_ip,omitempty"`
	Country    []string `json:"country,omitempty"`
	Method     []string `json:"method,omitempty"`
	PathExact  string   `json:"path_exact,omitempty"`
	PathPrefix string   `json:"path_prefix,omitempty"`
	PathRegex  string   `json:"path_regex,omitempty"`
	Host       string   `json:"host,omitempty"`
	Header     *KV      `json:"header,omitempty"`
	Query      *KV      `json:"query,omitempty"`
}

// KV matches a header or query parameter by name and value (substring or regex).
type KV struct {
	Name     string `json:"name"`
	Contains string `json:"contains,omitempty"`
	Regex    string `json:"regex,omitempty"`
}

type compiledKV struct {
	name     string
	contains string
	re       *regexp.Regexp
}

func compileKV(field string, kv *KV) (*compiledKV, error) {
	if kv == nil {
		return nil, nil
	}
	if kv.Name == "" {
		return nil, fmt.Errorf("match.%s.name: required", field)
	}
	if kv.Contains == "" && kv.Regex == "" {
		return nil, fmt.Errorf("match.%s: contains or regex required", field)
	}
	c := &compiledKV{name: kv.Name, contains: strings.ToLower(kv.Contains)}
	if kv.Regex != "" {
		re, err := regexp.Compile(kv.Regex)
		if err != nil {
			return nil, fmt.Errorf("match.%s.regex: %w", field, err)
		}
		c.re = re
	}
	return c, nil
}

func (c *compiledKV) matchAny(values []string) bool {
	for _, v := range values {
		if (c.contains != "" && strings.Contains(strings.ToLower(v), c.contains)) || (c.re != nil && c.re.MatchString(v)) {
			return true
		}
	}
	return false
}

// compiledRule is a Rule with parsed IP sets and compiled regexes.
type compiledRule struct {
	name      string
	action    string
	ip, notIP IPSet
	country   map[string]bool
	method    map[string]bool
	m         Match
	pathRe    *regexp.Regexp
	exactLC   string
	prefixLC  string
	header    *compiledKV
	query     *compiledKV
}

func compileRule(r Rule) (*compiledRule, error) {
	m := r.Match
	switch r.Action {
	case "block", "allow":
	default:
		return nil, fmt.Errorf("action: must be \"block\" or \"allow\", got %q", r.Action)
	}
	if len(m.IP) == 0 && len(m.NotIP) == 0 && len(m.Country) == 0 && len(m.Method) == 0 &&
		m.PathExact == "" && m.PathPrefix == "" && m.PathRegex == "" && m.Host == "" &&
		m.Header == nil && m.Query == nil {
		return nil, errors.New("match: at least one condition is required")
	}
	if r.Action == "allow" && len(m.IP) == 0 && m.PathExact == "" && m.PathPrefix == "" {
		return nil, errors.New("match: allow rules need ip, path_exact or path_prefix")
	}
	c := &compiledRule{
		name:     r.Name,
		action:   r.Action,
		m:        m,
		exactLC:  strings.ToLower(m.PathExact),
		prefixLC: strings.ToLower(m.PathPrefix),
	}
	var err error
	if c.ip, err = ParseIPSet(m.IP); err != nil {
		return nil, fmt.Errorf("match.ip: %w", err)
	}
	if c.notIP, err = ParseIPSet(m.NotIP); err != nil {
		return nil, fmt.Errorf("match.not_ip: %w", err)
	}
	if len(m.Country) > 0 {
		c.country = map[string]bool{}
		for _, cc := range m.Country {
			c.country[strings.ToUpper(strings.TrimSpace(cc))] = true
		}
	}
	if len(m.Method) > 0 {
		c.method = map[string]bool{}
		for _, me := range m.Method {
			c.method[strings.ToUpper(strings.TrimSpace(me))] = true
		}
	}
	if m.PathRegex != "" {
		if c.pathRe, err = regexp.Compile(m.PathRegex); err != nil {
			return nil, fmt.Errorf("match.path_regex: %w", err)
		}
	}
	if c.header, err = compileKV("header", m.Header); err != nil {
		return nil, err
	}
	if c.query, err = compileKV("query", m.Query); err != nil {
		return nil, err
	}
	return c, nil
}

// Validate checks the rule; error text names the offending field.
func (r Rule) Validate() error {
	_, err := compileRule(r)
	return err
}

// cleanPath normalises a request path the way lenient backends read it:
// backslashes become slashes, ";params" are cut from each segment (Tomcat and
// Spring ignore them, so "/static/..;/admin" reaches /admin), then dot
// segments and duplicate slashes are resolved. A trailing slash is kept;
// empty becomes "/".
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	p = strings.ReplaceAll(p, "\\", "/")
	if strings.Contains(p, ";") {
		segs := strings.Split(p, "/")
		for i, seg := range segs {
			if j := strings.IndexByte(seg, ';'); j >= 0 {
				segs[i] = seg[:j]
			}
		}
		p = strings.Join(segs, "/")
	}
	c := path.Clean("/" + p)
	if strings.HasSuffix(p, "/") && c != "/" {
		c += "/"
	}
	return c
}

// ambiguousPath reports whether the raw request path holds a ";" or a ".."
// segment (either slash direction). Backends disagree on such paths, so an
// allow rule never matches them: "/static/../admin" must not be let past the
// WAF by an allow rule for /static.
func ambiguousPath(r *http.Request) bool {
	for _, p := range []string{r.URL.Path, r.URL.RawPath} {
		if strings.Contains(p, ";") {
			return true
		}
		for _, seg := range strings.Split(strings.ReplaceAll(p, "\\", "/"), "/") {
			if seg == ".." {
				return true
			}
		}
	}
	return false
}

// matches reports whether all set conditions hold. country may be "" (unknown).
func (c *compiledRule) matches(r *http.Request, ip netip.Addr, country string) bool {
	m := c.m
	if c.action == "allow" && ambiguousPath(r) {
		return false
	}
	if len(c.ip) > 0 && !c.ip.Contains(ip) {
		return false
	}
	if len(c.notIP) > 0 {
		if !ip.IsValid() {
			// Unknown client IP: fail closed. not_ip counts as satisfied for
			// block rules and unsatisfied for allow rules.
			if c.action == "allow" {
				return false
			}
		} else if c.notIP.Contains(ip) {
			return false
		}
	}
	if c.country != nil && !c.country[country] {
		return false
	}
	if c.method != nil && !c.method[strings.ToUpper(r.Method)] {
		return false
	}
	p := cleanPath(r.URL.Path)
	lp := strings.ToLower(p)
	if c.exactLC != "" && lp != c.exactLC {
		return false
	}
	if c.prefixLC != "" && !strings.HasPrefix(lp, c.prefixLC) {
		return false
	}
	if c.pathRe != nil && !c.pathRe.MatchString(p) {
		return false
	}
	if m.Host != "" {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if !strings.EqualFold(host, m.Host) {
			return false
		}
	}
	if c.header != nil && !c.header.matchAny(r.Header.Values(c.header.name)) {
		return false
	}
	if c.query != nil && !c.query.matchAny(r.URL.Query()[c.query.name]) {
		return false
	}
	return true
}
