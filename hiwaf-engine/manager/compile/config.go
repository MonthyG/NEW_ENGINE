package compile

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"hostinginside/waf/engine/access"
	"hostinginside/waf/engine/auth"
	"hostinginside/waf/engine/challenge"
	"hostinginside/waf/engine/ratelimit"
	"hostinginside/waf/engine/waitroom"
	"hostinginside/waf/manager/site"
)

// Options are the engine-wide settings that aren't part of any site.
type Options struct {
	AdminListen                        string
	HTTPPort, HTTPSPort                int
	EventLog, ChallengeSecret, GeoIPDB string
	AccessLog                          string // per-request access log; empty = off
	TrustedProxies                     []string
	ACMEInternal                       bool
	FeedsDir                           string // block_ips_file names resolve inside it
	StaticDir                          string // static sites serve <StaticDir>/<site ID>
	ReservedPorts                      []int  // ports sites may not use (console, admin)
	CRSDir                             string // an unpacked CRS release to use instead of the built-in rules; empty = built-in
	PluginsDir                         string // the app profiles' CRS plugins, one directory per app (crsplugins.Install)

	// EventLogNet and AccessLogNet are Caddy network addresses (unix//data/events.sock)
	// the engine streams those logs to instead, for a manager on another host. The
	// events still go to EventLog too, so a dropped stream can be recovered by hand.
	EventLogNet, AccessLogNet string
}

func (o Options) accessLogOn() bool { return o.AccessLog != "" || o.AccessLogNet != "" }

// netWriter streams a log to addr. soft_start keeps the engine starting while
// the manager's end is down; lines written meanwhile are dropped.
func netWriter(addr string) map[string]any {
	return map[string]any{"output": "net", "address": addr, "soft_start": true}
}

// engineLoggers are the Caddy loggers whose lines go to the events file.
var engineLoggers = []string{
	"http.handlers.waf",
	"http.handlers.hi_access",
	"http.handlers.hi_ratelimit",
	"http.handlers.hi_challenge",
	"http.handlers.hi_auth",
	"http.handlers.hi_waitroom",
}

// accessLogger is the parent of Caddy's per-host access loggers.
const accessLogger = "http.log.access"

// Handler JSON: the module's own config with Caddy's "handler" key in front.
type accessHandler struct {
	Handler string `json:"handler"`
	access.Access
}

type rateLimitHandler struct {
	Handler string `json:"handler"`
	ratelimit.RateLimit
}

type challengeHandler struct {
	Handler string `json:"handler"`
	challenge.Challenge
}

type authHandler struct {
	Handler string `json:"handler"`
	auth.Auth
}

type waitRoomHandler struct {
	Handler string `json:"handler"`
	waitroom.WaitRoom
}

// listenPlan is what one port serves: whether it is TLS, the sites it serves
// and the sites it redirects to an HTTPS port.
type listenPlan struct {
	port      int
	https     bool
	serve     []site.Resolved
	redirects []redirect
}

type redirect struct {
	site site.Resolved
	to   int
}

// sitePorts returns s's listening ports: its own, or the global HTTP port
// plus, unless TLS is off, the global HTTPS port.
func sitePorts(s site.Resolved, opt Options) []site.PortDoc {
	if len(s.Ports) > 0 {
		return s.Ports
	}
	if s.TLSMode == "off" {
		return []site.PortDoc{{Port: opt.HTTPPort}}
	}
	return []site.PortDoc{{Port: opt.HTTPPort}, {Port: opt.HTTPSPort, HTTPS: true}}
}

// plan assigns every site to its ports.
func plan(sites []site.Resolved, opt Options) ([]*listenPlan, error) {
	reserved := map[int]bool{}
	for _, p := range opt.ReservedPorts {
		reserved[p] = true
	}
	plans := map[int]*listenPlan{}
	for _, s := range sites {
		ports := sitePorts(s, opt)
		firstTLS := 0
		for _, p := range ports {
			if p.HTTPS {
				firstTLS = p.Port
				break
			}
		}
		for _, p := range ports {
			if reserved[p.Port] {
				return nil, fmt.Errorf("site %s: port %d is reserved for the WAF itself", s.ID, p.Port)
			}
			if p.HTTPS && p.Port == opt.HTTPPort {
				return nil, fmt.Errorf("site %s: port %d is the plain HTTP port and can't be HTTPS", s.ID, p.Port)
			}
			if !p.HTTPS && p.Port == opt.HTTPSPort {
				return nil, fmt.Errorf("site %s: port %d is the HTTPS port and can't be plain HTTP", s.ID, p.Port)
			}
			lp, ok := plans[p.Port]
			if !ok {
				lp = &listenPlan{port: p.Port, https: p.HTTPS}
				plans[p.Port] = lp
			} else if lp.https != p.HTTPS {
				return nil, fmt.Errorf("site %s: port %d is used as both HTTP and HTTPS", s.ID, p.Port)
			}
			if !p.HTTPS && s.TLSMode != "off" && s.HTTPRedirect && firstTLS > 0 {
				lp.redirects = append(lp.redirects, redirect{site: s, to: firstTLS})
			} else {
				lp.serve = append(lp.serve, s)
			}
		}
	}
	out := make([]*listenPlan, 0, len(plans))
	for _, lp := range plans {
		out = append(out, lp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].port < out[j].port })
	return out, nil
}

// serverName keeps the historical names for the global ports.
func serverName(lp *listenPlan, opt Options) string {
	switch {
	case lp.https && lp.port == opt.HTTPSPort:
		return "waf"
	case !lp.https && lp.port == opt.HTTPPort:
		return "plain"
	}
	return fmt.Sprintf("p%d", lp.port)
}

// certFor returns the stored certificate of an uploaded-TLS site: the global
// certificate it names, or the legacy per-site one.
func certFor(s site.Resolved, certs map[string]site.Cert) (site.Cert, string, bool) {
	key := s.ID
	if s.CertID != "" {
		key = s.CertID
	}
	c, ok := certs[key]
	return c, key, ok && c.CertPEM != "" && c.KeyPEM != ""
}

// Config compiles every site into one complete Caddy config. certs is keyed
// by certificate ID or, for legacy per-site certificates, by site ID.
func Config(sites []site.Resolved, certs map[string]site.Cert, opt Options) (map[string]any, error) {
	var pems []any
	loaded := map[string]bool{}
	for _, s := range sites {
		if s.BlockIPsFile != "" && opt.FeedsDir == "" {
			return nil, fmt.Errorf("site %s: block_ips_file is set but no feeds directory is configured", s.ID)
		}
		if s.Type == "static" && opt.StaticDir == "" {
			return nil, fmt.Errorf("site %s: static sites need a static directory", s.ID)
		}
		if s.TLSMode == "uploaded" {
			c, key, ok := certFor(s, certs)
			if !ok {
				return nil, fmt.Errorf("site %s: tls mode is uploaded but no certificate is stored", s.ID)
			}
			if !loaded[key] {
				loaded[key] = true
				pems = append(pems, map[string]any{"certificate": c.CertPEM, "key": c.KeyPEM, "tags": []string{key}})
			}
		}
		for _, u := range s.AuthUsers {
			if s.AuthEnabled && u.PasswordHash == "" {
				return nil, fmt.Errorf("site %s: auth user %q has no password hash", s.ID, u.Username)
			}
		}
	}
	plans, err := plan(sites, opt)
	if err != nil {
		return nil, err
	}

	// Caddy's own HTTP->HTTPS redirects are off: it would put them after our
	// host routes on the plain server (so a plain *.a.com would catch a TLS
	// x.a.com) and skip them when every TLS site has an uploaded cert. Plain
	// servers carry explicit redirects instead.
	servers := map[string]any{}
	for _, lp := range plans {
		srv := server(lp, opt)
		if lp.https {
			autoHTTPS := map[string]any{"disable_redirects": true}
			var skip []string
			for _, s := range lp.serve {
				if s.TLSMode == "uploaded" {
					skip = append(skip, s.Domains...)
				}
			}
			if len(skip) > 0 {
				autoHTTPS["skip_certificates"] = skip
			}
			srv["automatic_https"] = autoHTTPS
		} else if lp.port != opt.HTTPPort {
			// Caddy would otherwise turn a host-matched server on a port
			// other than http_port into an HTTPS server.
			srv["automatic_https"] = map[string]any{"disable": true}
		}
		servers[serverName(lp, opt)] = srv
	}
	httpApp := map[string]any{"http_port": opt.HTTPPort, "https_port": opt.HTTPSPort}
	if len(servers) > 0 {
		httpApp["servers"] = servers
	}
	apps := map[string]any{"http": httpApp}

	tlsApp := map[string]any{}
	if len(pems) > 0 {
		tlsApp["certificates"] = map[string]any{"load_pem": pems}
	}
	if opt.ACMEInternal {
		tlsApp["automation"] = map[string]any{"policies": []any{
			map[string]any{"issuers": []any{map[string]any{"module": "internal"}}},
		}}
	}
	if len(tlsApp) > 0 {
		apps["tls"] = tlsApp
	}
	// Caddy's local CA (internal issuer, and the fallback for names ACME
	// can't serve) would otherwise install its root into the host's trust
	// store, prompting on desktops; a WAF server has no use for that.
	apps["pki"] = map[string]any{"certificate_authorities": map[string]any{
		"local": map[string]any{"install_trust": false},
	}}

	defaultExclude := append([]string(nil), engineLoggers...)
	logs := map[string]any{
		"hi_events": map[string]any{
			"writer":  map[string]any{"output": "file", "filename": opt.EventLog, "roll_size_mb": 100},
			"encoder": map[string]any{"format": "json"},
			"include": engineLoggers,
		},
	}
	if opt.EventLogNet != "" {
		logs["hi_events_net"] = map[string]any{
			"writer":  netWriter(opt.EventLogNet),
			"encoder": map[string]any{"format": "json"},
			"include": engineLoggers,
		}
	}
	if opt.accessLogOn() {
		defaultExclude = append(defaultExclude, accessLogger)
		w := map[string]any{"output": "file", "filename": opt.AccessLog, "roll_size_mb": 200, "roll_keep": 5}
		if opt.AccessLogNet != "" {
			w = netWriter(opt.AccessLogNet)
		}
		logs["hi_access"] = map[string]any{
			"writer":  w,
			"encoder": map[string]any{"format": "json"},
			"include": []string{accessLogger},
		}
	}
	logs["default"] = map[string]any{"exclude": defaultExclude}

	return map[string]any{
		"admin":   map[string]any{"listen": opt.AdminListen},
		"logging": map[string]any{"logs": logs},
		"apps":    apps,
	}, nil
}

// server builds one HTTP server. Routes for exact domains (served and
// redirected alike) come before wildcard domains, so x.a.com wins over
// *.a.com whatever the site order; a match-all (*) site comes last and
// otherwise a 404 fallback does.
func server(lp *listenPlan, opt Options) map[string]any {
	var routes, errRoutes []any
	loggerNames := map[string]any{}
	catchAll := ""
	for _, wildcard := range []bool{false, true} {
		for _, s := range lp.serve {
			hosts := hostsOf(s, wildcard)
			if len(hosts) == 0 {
				continue
			}
			match := []any{map[string]any{"host": hosts}}
			routes = append(routes, map[string]any{
				"match":    match,
				"handle":   []any{map[string]any{"handler": "subroute", "routes": siteRoutes(s, opt, lp.https)}},
				"terminal": true,
			})
			errRoutes = append(errRoutes, blockPages(s, match)...)
			for _, h := range hosts {
				loggerNames[h] = s.ID
			}
		}
		for _, rd := range lp.redirects {
			hosts := hostsOf(rd.site, wildcard)
			if len(hosts) == 0 {
				continue
			}
			location := "https://{http.request.host}{http.request.uri}"
			if rd.to != 443 {
				location = fmt.Sprintf("https://{http.request.host}:%d{http.request.uri}", rd.to)
			}
			routes = append(routes, map[string]any{
				"match": []any{map[string]any{"host": hosts}},
				"handle": []any{map[string]any{
					"handler":     "static_response",
					"status_code": 308,
					"headers":     map[string]any{"Location": []string{location}},
				}},
				"terminal": true,
			})
		}
	}
	for _, s := range lp.serve {
		if !matchAll(s) {
			continue
		}
		catchAll = s.ID
		routes = append(routes, map[string]any{
			"handle":   []any{map[string]any{"handler": "subroute", "routes": siteRoutes(s, opt, lp.https)}},
			"terminal": true,
		})
		errRoutes = append(errRoutes, blockPages(s, nil)...)
		break // validation allows one * per port; the first wins
	}
	if catchAll == "" {
		routes = append(routes, map[string]any{
			"handle": []any{map[string]any{"handler": "static_response", "status_code": 404, "body": "unknown site"}},
		})
	}
	srv := map[string]any{
		"listen": []string{fmt.Sprintf(":%d", lp.port)},
		"routes": routes,
	}
	if len(errRoutes) > 0 {
		srv["errors"] = map[string]any{"routes": errRoutes}
	}
	if opt.accessLogOn() && (len(loggerNames) > 0 || catchAll != "") {
		logCfg := map[string]any{"skip_unmapped_hosts": catchAll == ""}
		if len(loggerNames) > 0 {
			logCfg["logger_names"] = loggerNames
		}
		if catchAll != "" {
			logCfg["default_logger_name"] = catchAll
		}
		srv["logs"] = logCfg
	}
	if len(opt.TrustedProxies) > 0 {
		srv["trusted_proxies"] = map[string]any{"source": "static", "ranges": opt.TrustedProxies}
		// Strict mode reads X-Forwarded-For right to left, skipping trusted
		// hops; the default left-to-right parse takes the first (client
		// controlled) value, letting anyone spoof an allow_ips address.
		srv["trusted_proxies_strict"] = 1
	}
	return srv
}

func matchAll(s site.Resolved) bool {
	for _, d := range s.Domains {
		if d == "*" {
			return true
		}
	}
	return false
}

// hostsOf returns s's wildcard (*.) domains or its exact domains; the
// match-all "*" is never returned.
func hostsOf(s site.Resolved, wildcard bool) []string {
	var hosts []string
	for _, d := range s.Domains {
		if d == "*" {
			continue
		}
		if strings.HasPrefix(d, "*.") == wildcard {
			hosts = append(hosts, d)
		}
	}
	return hosts
}

// terminal is the handler that produces the site's content.
func terminal(s site.Resolved, opt Options) map[string]any {
	switch s.Type {
	case "static":
		return map[string]any{
			"handler": "file_server",
			"root":    filepath.Join(opt.StaticDir, s.ID),
		}
	case "redirect":
		loc := s.RedirectURL
		if s.PreservePath {
			loc = strings.TrimSuffix(loc, "/") + "{http.request.uri}"
		}
		return map[string]any{
			"handler":     "static_response",
			"status_code": s.RedirectCode,
			"headers":     map[string]any{"Location": []string{loc}},
		}
	}
	return reverseProxy(s)
}

// siteRoutes is the site's handler chain: access, then an allowlist bypass
// straight to the content, then rate limit, auth, waiting room, challenge,
// WAF, compression and the content handler.
func siteRoutes(s site.Resolved, opt Options, tls bool) []any {
	content := []any{}
	if s.Gzip {
		content = append(content, map[string]any{
			"handler":   "encode",
			"encodings": map[string]any{"gzip": map[string]any{}, "zstd": map[string]any{}},
			"prefer":    []string{"zstd", "gzip"},
		})
	}
	content = append(content, terminal(s, opt))

	// A request that already passed through this WAF (an upstream pointing
	// back at the WAF, or two sites proxying to each other) stops here
	// instead of multiplying until the engine runs out of connections.
	routes := []any{map[string]any{
		"match":    []any{map[string]any{"header": map[string]any{LoopHeader: []string{}}}},
		"handle":   []any{map[string]any{"handler": "static_response", "status_code": 508, "body": "loop detected: this site's origin points back at the WAF"}},
		"terminal": true,
	}}
	if tls && s.HSTS {
		routes = append(routes, map[string]any{"handle": []any{map[string]any{
			"handler":  "headers",
			"response": map[string]any{"set": map[string]any{"Strict-Transport-Security": []string{"max-age=31536000"}}},
		}}})
	}
	if hasAccess(s) {
		routes = append(routes, map[string]any{"handle": []any{accessHandler{
			Handler: "hi_access",
			Access: access.Access{
				SiteID:         s.ID,
				AllowIPs:       s.AllowIPs,
				BlockIPs:       s.BlockIPs,
				AllowCountries: s.AllowCountries,
				BlockCountries: s.BlockCountries,
				BlockIPsFile:   feedPath(opt.FeedsDir, s.BlockIPsFile),
				GeoIPDB:        opt.GeoIPDB,
				Rules:          s.Rules,
			},
		}}})
	}
	routes = append(routes, map[string]any{
		"match":    []any{map[string]any{"vars": map[string]any{"{http.vars." + access.SkipVar + "}": []string{"true"}}}},
		"handle":   content,
		"terminal": true,
	})
	main := []any{rateLimitHandler{
		Handler:   "hi_ratelimit",
		RateLimit: ratelimit.RateLimit{SiteID: s.ID, Access: s.Access, Attack: s.Attack, Error: s.Error},
	}}
	if s.AuthEnabled {
		users := make([]auth.User, 0, len(s.AuthUsers))
		for _, u := range s.AuthUsers {
			users = append(users, auth.User{Username: u.Username, PasswordHash: u.PasswordHash})
		}
		title := "Authentication required"
		if s.Name != "" {
			title = s.Name + " - sign in"
		}
		main = append(main, authHandler{
			Handler: "hi_auth",
			Auth:    auth.Auth{SiteID: s.ID, Secret: opt.ChallengeSecret, Users: users, SessionTTLSec: s.AuthTTL, Title: title},
		})
	}
	if s.WaitEnabled {
		main = append(main, waitRoomHandler{
			Handler:  "hi_waitroom",
			WaitRoom: waitroom.WaitRoom{SiteID: s.ID, Secret: opt.ChallengeSecret, MaxActive: s.WaitMax, SessionTTLSec: s.WaitTTL},
		})
	}
	if s.Challenge {
		main = append(main, challengeHandler{
			Handler:   "hi_challenge",
			Challenge: challenge.Challenge{SiteID: s.ID, Secret: opt.ChallengeSecret, Difficulty: s.ChallengeDifficulty},
		})
	}
	if s.WAFMode != "off" {
		main = append(main, map[string]any{
			"handler":          "waf",
			"load_owasp_crs":   true,
			"directives":       Directives(s, opt.CRSDir, opt.PluginsDir),
			"tx_id_req_header": ratelimit.TxHeader,
		})
	}
	main = append(main, content...)
	return append(routes, map[string]any{"handle": main})
}

// feedPath places a validated plain feed file name inside the feeds directory.
func feedPath(dir, name string) string {
	if name == "" {
		return ""
	}
	return filepath.Join(dir, name)
}

func hasAccess(s site.Resolved) bool {
	return len(s.AllowIPs) > 0 || len(s.BlockIPs) > 0 || len(s.AllowCountries) > 0 ||
		len(s.BlockCountries) > 0 || s.BlockIPsFile != "" || len(s.Rules) > 0
}

// LoopHeader marks requests the engine forwards to an origin; one arriving
// with it came back from this WAF and is refused (508).
const LoopHeader = "Hi-Waf-Loop"

// reverseProxy dials each upstream without its scheme; https upstreams (the
// validator keeps all upstreams on one scheme) get a TLS transport.
func reverseProxy(s site.Resolved) map[string]any {
	var list []any
	useTLS := false
	for _, u := range s.Upstreams {
		if rest, ok := strings.CutPrefix(u, "https://"); ok {
			useTLS, u = true, rest
		} else {
			u = strings.TrimPrefix(u, "http://")
		}
		list = append(list, map[string]any{"dial": u})
	}
	reqHeaders := map[string]any{"delete": []string{ratelimit.TxHeader}}
	set := map[string]any{LoopHeader: []string{"1"}}
	if !s.KeepHost {
		set["Host"] = []string{"{http.reverse_proxy.upstream.hostport}"}
	}
	reqHeaders["set"] = set
	h := map[string]any{
		"handler":   "reverse_proxy",
		"upstreams": list,
		"headers":   map[string]any{"request": reqHeaders},
	}
	if len(list) > 1 || (s.LBPolicy != "" && s.LBPolicy != "round_robin") {
		policy := s.LBPolicy
		if policy == "" {
			policy = "round_robin"
		}
		h["load_balancing"] = map[string]any{"selection_policy": map[string]any{"policy": policy}}
		h["health_checks"] = map[string]any{"passive": map[string]any{"fail_duration": "30s", "max_fails": 3}}
	}
	if useTLS {
		tlsCfg := map[string]any{}
		if s.KeepHost {
			// Upstreams are IPs; without this the origin is asked for, and its
			// certificate checked against, that IP instead of the site's domain.
			tlsCfg["server_name"] = "{http.request.host}"
		}
		h["transport"] = map[string]any{"protocol": "http", "tls": tlsCfg}
	}
	return h
}
