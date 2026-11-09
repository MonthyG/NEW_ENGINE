package ratelimit

import "net/netip"

// ipv6PrefixBits is the IPv6 prefix that limits and bans apply to. One IPv6
// client typically holds a whole /64, so keying on the full address would let
// it use a fresh address for every request and never reach a limit.
const ipv6PrefixBits = 64

// Key returns the limiter key for a client IP: an IPv4 address as is, or the
// /64 of an IPv6 address ("2001:db8:1:2::/64"). A string that doesn't parse
// is returned unchanged.
func Key(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.WithZone("").Prefix(ipv6PrefixBits)
	return p.String()
}

// adminKey turns the ip given to the ban admin into a limiter key. It takes
// a plain address (any address inside a banned /64 works) or the /64 prefix
// as the ban list shows it.
func adminKey(s string) string {
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is6() && !p.Addr().Is4In6() && p.Bits() == ipv6PrefixBits {
		return p.Masked().String()
	}
	return Key(s)
}
