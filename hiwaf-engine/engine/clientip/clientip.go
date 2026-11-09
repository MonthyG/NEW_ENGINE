// Package clientip resolves the real client IP of a request.
package clientip

import (
	"net"
	"net/http"
	"net/netip"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// Get returns the client IP as a string. It uses the Caddy client_ip var
// (which honours Caddy's trusted_proxies setting) when set, otherwise the host
// part of r.RemoteAddr. The result is unmapped so IPv4-mapped IPv6 addresses
// become plain IPv4. If nothing parses, the raw host string is returned.
func Get(r *http.Request) string {
	if v, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && v != "" {
		return unmap(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return unmap(host)
}

func unmap(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return s
	}
	return a.Unmap().String()
}
