package site

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"hostinginside/waf/engine/access"
)

// IPGroup is a named, reusable list of IPs and CIDRs (Settings > IP Groups).
type IPGroup struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	IPs         []string `json:"ips"`
}

// GlobalRule is a custom rule (Allow & Deny > Custom Rules) applied to every
// site, or to the listed sites, before the site's own rules.
type GlobalRule struct {
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	Action      string       `json:"action"`          // allow | block
	Sites       []string     `json:"sites,omitempty"` // empty = all sites
	IPGroups    []string     `json:"ip_groups,omitempty"`
	NotIPGroups []string     `json:"not_ip_groups,omitempty"`
	Match       access.Match `json:"match"`
	Priority    int          `json:"priority,omitempty"` // lower runs first
}

// Certificate is an uploaded certificate (Settings > Certificates).
type Certificate struct {
	Name    string `json:"name"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
}

// Globals are the objects shared by sites. Rules must be ordered.
type Globals struct {
	Groups map[string]IPGroup
	Rules  []IDRule
	Certs  map[string]Certificate
}

// IDRule is a GlobalRule with its ID.
type IDRule struct {
	ID string
	GlobalRule
}

// NewObjectID returns prefix + "_" + 12 lowercase hex characters.
func NewObjectID(prefix string) string {
	var b [6]byte
	_, _ = rand.Read(b[:]) // never fails since Go 1.24
	return prefix + "_" + hex.EncodeToString(b[:])
}

// ValidateIPGroup checks a group.
func ValidateIPGroup(g IPGroup) error {
	if strings.TrimSpace(g.Name) == "" || utf8.RuneCountInString(g.Name) > 64 {
		return verr("name", "must be 1-64 characters")
	}
	if utf8.RuneCountInString(g.Description) > 500 {
		return verr("description", "must be at most 500 characters")
	}
	if len(g.IPs) > 10000 {
		return verr("ips", "at most 10000 entries")
	}
	if _, err := access.ParseIPSet(g.IPs); err != nil {
		return verr("ips", "%s", err.Error())
	}
	return nil
}

// ValidateGlobalRule checks a rule. Group references are checked in
// ApplyGlobals, when the groups are known.
func ValidateGlobalRule(r GlobalRule, geoEnabled bool) error {
	if strings.TrimSpace(r.Name) == "" || utf8.RuneCountInString(r.Name) > 64 {
		return verr("name", "must be 1-64 characters")
	}
	if err := validateCountries("match.country", r.Match.Country, geoEnabled); err != nil {
		return err
	}
	probe := access.Rule{Name: r.Name, Action: r.Action, Match: r.Match}
	if len(r.IPGroups) > 0 && len(probe.Match.IP) == 0 {
		probe.Match.IP = []string{"0.0.0.0/32"} // stands in for the groups
	}
	if len(r.NotIPGroups) > 0 && len(probe.Match.NotIP) == 0 {
		probe.Match.NotIP = []string{"0.0.0.0/32"}
	}
	if err := probe.Validate(); err != nil {
		return verr("match", "%s", err.Error())
	}
	return nil
}

// groupIPs expands group IDs into their IPs.
func groupIPs(g Globals, field string, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		grp, ok := g.Groups[id]
		if !ok {
			return nil, verr(field, "unknown IP group %q", id)
		}
		out = append(out, grp.IPs...)
	}
	return out, nil
}

// ApplyGlobals expands r's IP groups and prepends the enabled global rules
// that apply to r. It fails on references to missing groups or certificates.
func ApplyGlobals(r *Resolved, g Globals) error {
	allow, err := groupIPs(g, "access.allow_groups", r.AllowGroups)
	if err != nil {
		return err
	}
	block, err := groupIPs(g, "access.block_groups", r.BlockGroups)
	if err != nil {
		return err
	}
	r.AllowIPs = append(r.AllowIPs, allow...)
	r.BlockIPs = append(r.BlockIPs, block...)
	if r.TLSMode == "uploaded" && r.CertID != "" {
		if _, ok := g.Certs[r.CertID]; !ok {
			return verr("tls.cert_id", "unknown certificate %q", r.CertID)
		}
	}

	var pre []access.Rule
	for _, gr := range g.Rules {
		if !gr.Enabled || !appliesTo(gr.Sites, r.ID) {
			continue
		}
		m := gr.Match
		ips, err := groupIPs(g, "rule "+gr.Name, gr.IPGroups)
		if err != nil {
			return err
		}
		notIPs, err := groupIPs(g, "rule "+gr.Name, gr.NotIPGroups)
		if err != nil {
			return err
		}
		m.IP = append(append([]string(nil), m.IP...), ips...)
		m.NotIP = append(append([]string(nil), m.NotIP...), notIPs...)
		if len(gr.IPGroups) > 0 && len(m.IP) == 0 {
			// An empty group must match nobody, not everybody.
			m.IP = []string{"255.255.255.255/32"}
		}
		pre = append(pre, access.Rule{Name: gr.Name, Action: gr.Action, Match: m})
	}
	r.Rules = append(pre, r.Rules...)
	return nil
}

func appliesTo(sites []string, id string) bool {
	if len(sites) == 0 {
		return true
	}
	for _, s := range sites {
		if s == id {
			return true
		}
	}
	return false
}

// CheckGroupUnused reports an error if any site or rule references group id.
func CheckGroupUnused(id string, docs map[string]Doc, rules []IDRule) error {
	for sid, d := range docs {
		if d.Access == nil {
			continue
		}
		for _, l := range [][]string{d.Access.AllowGroups, d.Access.BlockGroups} {
			for _, g := range l {
				if g == id {
					return fmt.Errorf("IP group is used by site %s", sid)
				}
			}
		}
	}
	for _, r := range rules {
		for _, l := range [][]string{r.IPGroups, r.NotIPGroups} {
			for _, g := range l {
				if g == id {
					return fmt.Errorf("IP group is used by rule %q", r.Name)
				}
			}
		}
	}
	return nil
}
