package access

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/oschwald/geoip2-golang"
	"go.uber.org/zap"

	"hostinginside/waf/engine/clientip"
	"hostinginside/waf/engine/events"
)

// SkipVar is the request var set to "true" when later WAF/challenge handlers
// must be skipped.
const SkipVar = "hi_skip"

func init() {
	caddy.RegisterModule(Access{})
}

// Access is the http.handlers.hi_access middleware.
type Access struct {
	SiteID         string   `json:"site_id"`
	AllowIPs       []string `json:"allow_ips,omitempty"`
	BlockIPs       []string `json:"block_ips,omitempty"`
	AllowCountries []string `json:"allow_countries,omitempty"`
	BlockCountries []string `json:"block_countries,omitempty"`
	BlockIPsFile   string   `json:"block_ips_file,omitempty"`
	GeoIPDB        string   `json:"geoip_db,omitempty"`
	Rules          []Rule   `json:"rules,omitempty"`

	allow, block   IPSet
	allowC, blockC map[string]bool
	rules          []*compiledRule
	countryOf      func(netip.Addr) string
	geo            *geoip2.Reader
	logger         *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (Access) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.hi_access",
		New: func() caddy.Module { return new(Access) },
	}
}

// Provision parses lists, reads block_ips_file and opens the GeoIP database.
func (a *Access) Provision(ctx caddy.Context) error {
	a.logger = ctx.Logger()
	var err error
	if a.allow, err = ParseIPSet(a.AllowIPs); err != nil {
		return fmt.Errorf("allow_ips: %w", err)
	}
	if a.block, err = ParseIPSet(a.BlockIPs); err != nil {
		return fmt.Errorf("block_ips: %w", err)
	}
	if a.BlockIPsFile != "" {
		fileSet, err := readIPFile(a.BlockIPsFile)
		if err != nil {
			return err
		}
		a.block = append(a.block, fileSet...)
	}
	a.allowC, a.blockC = upperSet(a.AllowCountries), upperSet(a.BlockCountries)
	a.rules = nil
	for i, r := range a.Rules {
		c, err := compileRule(r)
		if err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		a.rules = append(a.rules, c)
	}
	if a.GeoIPDB != "" {
		a.geo, err = geoip2.Open(a.GeoIPDB)
		if err != nil {
			return fmt.Errorf("geoip_db: %w", err)
		}
		a.countryOf = a.lookupCountry
	}
	return nil
}

// lookupCountry returns the upper-case ISO country code, or "" if unknown.
func (a *Access) lookupCountry(addr netip.Addr) string {
	rec, err := a.geo.Country(net.IP(addr.Unmap().AsSlice()))
	if err != nil || rec == nil {
		return ""
	}
	return strings.ToUpper(rec.Country.IsoCode)
}

func upperSet(list []string) map[string]bool {
	m := make(map[string]bool, len(list))
	for _, c := range list {
		m[strings.ToUpper(strings.TrimSpace(c))] = true
	}
	return m
}

// readIPFile reads one IP/CIDR per line; blank lines and # comments are ignored.
func readIPFile(path string) (IPSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("block_ips_file: %w", err)
	}
	defer f.Close()
	var set IPSet
	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		s, err := ParseIPSet([]string{line})
		if err != nil {
			return nil, fmt.Errorf("block_ips_file line %d: %w", n, err)
		}
		set = append(set, s...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("block_ips_file: %w", err)
	}
	return set, nil
}

// Validate checks the config.
func (a *Access) Validate() error {
	if a.SiteID == "" {
		return errors.New("site_id is required")
	}
	if _, err := ParseIPSet(a.AllowIPs); err != nil {
		return fmt.Errorf("allow_ips: %w", err)
	}
	if _, err := ParseIPSet(a.BlockIPs); err != nil {
		return fmt.Errorf("block_ips: %w", err)
	}
	needGeo := len(a.AllowCountries) > 0 || len(a.BlockCountries) > 0
	for i, r := range a.Rules {
		if err := r.Validate(); err != nil {
			return fmt.Errorf("rules[%d]: %w", i, err)
		}
		if len(r.Match.Country) > 0 {
			needGeo = true
		}
	}
	if needGeo && a.GeoIPDB == "" {
		return errors.New("geoip_db is required when countries are configured")
	}
	return nil
}

// Cleanup closes the GeoIP database.
func (a *Access) Cleanup() error {
	if a.geo != nil {
		err := a.geo.Close()
		a.geo = nil
		return err
	}
	return nil
}

func (a *Access) deny(r *http.Request, typ, detail string) error {
	e := events.FromRequest(r, typ, a.SiteID)
	e.Msg = detail
	events.Emit(a.logger, e)
	events.Tag(r, events.ActionDeny, typ)
	return caddyhttp.Error(http.StatusForbidden, errors.New("access denied"))
}

// ServeHTTP applies allow IPs, block IPs, geo rules and custom rules in order.
func (a *Access) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// An unparseable client IP gets the zero Addr: it matches no IP list,
	// ip or country condition, but non-IP rules still apply.
	ip, _ := netip.ParseAddr(clientip.Get(r))
	ip = ip.Unmap()

	if a.allow.Contains(ip) {
		caddyhttp.SetVar(r.Context(), SkipVar, "true")
		events.Tag(r, events.ActionAllow, "")
		return next.ServeHTTP(w, r)
	}
	if a.block.Contains(ip) {
		return a.deny(r, events.TypeIPBlock, "")
	}

	country := ""
	if a.countryOf != nil && ip.IsValid() {
		country = strings.ToUpper(a.countryOf(ip))
	}
	// An allow list means "only these": a public address GeoIP can't place is
	// not on it. Private and loopback addresses have no country and still pass.
	if country == "" && len(a.allowC) > 0 && ip.IsGlobalUnicast() && !ip.IsPrivate() {
		return a.deny(r, events.TypeGeoBlock, "unknown")
	}
	if country != "" {
		if len(a.allowC) > 0 && !a.allowC[country] {
			return a.deny(r, events.TypeGeoBlock, country)
		}
		if a.blockC[country] {
			return a.deny(r, events.TypeGeoBlock, country)
		}
	}

	for _, rule := range a.rules {
		if !rule.matches(r, ip, country) {
			continue
		}
		if rule.action == "block" {
			return a.deny(r, events.TypeRuleBlock, rule.name)
		}
		e := events.FromRequest(r, events.TypeAllowedByRule, a.SiteID)
		e.Msg = rule.name
		events.Emit(a.logger, e)
		events.Tag(r, events.ActionAllow, events.TypeAllowedByRule)
		caddyhttp.SetVar(r.Context(), SkipVar, "true")
		return next.ServeHTTP(w, r)
	}
	return next.ServeHTTP(w, r)
}

// Interface guards.
var (
	_ caddy.Provisioner           = (*Access)(nil)
	_ caddy.Validator             = (*Access)(nil)
	_ caddy.CleanerUpper          = (*Access)(nil)
	_ caddyhttp.MiddlewareHandler = (*Access)(nil)
)
