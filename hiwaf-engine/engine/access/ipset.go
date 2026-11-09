// Package access implements http.handlers.hi_access: IP allow/block lists,
// country blocking and custom rules.
package access

import (
	"fmt"
	"net/netip"
	"strings"
)

// IPSet is a set of IP prefixes. A bare IP is stored as a /32 or /128.
type IPSet []netip.Prefix

// ParseIPSet parses bare IPs and CIDRs.
func ParseIPSet(entries []string) (IPSet, error) {
	set := make(IPSet, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if p, err := netip.ParsePrefix(e); err == nil {
			if p.Addr().Is4In6() && p.Bits() < 96 {
				return nil, fmt.Errorf("invalid IP or CIDR %q: IPv4-mapped prefix shorter than /96", e)
			}
			set = append(set, netip.PrefixFrom(p.Addr().Unmap(), unmapBits(p)).Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("invalid IP or CIDR %q", e)
		}
		a = a.Unmap()
		set = append(set, netip.PrefixFrom(a, a.BitLen()))
	}
	return set, nil
}

// unmapBits converts the length of an IPv4-mapped IPv6 prefix
// (::ffff:a.b.c.d/N) to the IPv4 length.
func unmapBits(p netip.Prefix) int {
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		return p.Bits() - 96
	}
	return p.Bits()
}

// Contains reports whether a is in the set. IPv4-mapped IPv6 is unmapped first.
func (s IPSet) Contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range s {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
