package ratelimit

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestKey(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4":                    "1.2.3.4",
		"::ffff:1.2.3.4":             "1.2.3.4",
		"2001:db8:1:2:aaaa::1":       "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff:ffff::99": "2001:db8:1:2::/64",
		"fe80::1%eth0":               "fe80::/64",
		"not-an-ip":                  "not-an-ip",
	} {
		assert.Equal(t, want, Key(in), in)
	}
}

func TestAdminKey(t *testing.T) {
	for in, want := range map[string]string{
		"2001:db8:1:2::/64":    "2001:db8:1:2::/64",
		"2001:db8:1:2::5/64":   "2001:db8:1:2::/64",
		"2001:db8:1:2:aaaa::1": "2001:db8:1:2::/64",
		"10.0.0.1":             "10.0.0.1",
		"::ffff:10.0.0.1":      "10.0.0.1",
	} {
		assert.Equal(t, want, adminKey(in), in)
	}
}

// A client rotating through addresses in one /64 shares one counter.
func TestIPv6RotationWithinPrefixIsBanned(t *testing.T) {
	s := NewState()
	now := time.Unix(1000, 0)
	lim := Limit{Requests: 3, WindowSec: 10, BanSec: 60}
	ips := []string{"2001:db8::1", "2001:db8::2", "2001:db8::3:4", "2001:db8::ffff"}
	var banned bool
	for _, ip := range ips {
		_, banned = s.Record(KindAttack, Key(ip), lim, now)
	}
	assert.True(t, banned)
	_, b := s.BannedUntil(Key("2001:db8::abcd"), now)
	assert.True(t, b, "another address in the /64 is banned too")
	_, b = s.BannedUntil(Key("2001:db8:0:1::1"), now)
	assert.False(t, b, "the next /64 is not")
}

func TestWindowsCapped(t *testing.T) {
	s := NewState()
	now := time.Unix(1000, 0)
	lim := Limit{Requests: 100, WindowSec: 10, BanSec: 60}
	for i := 0; i < maxWindows+5000; i++ {
		s.Record(KindAccess, "k"+strconv.Itoa(i), lim, now)
	}
	assert.LessOrEqual(t, len(s.windows), maxWindows)
	assert.Greater(t, len(s.windows), maxWindows-maxWindows/10-5000)
}

// The cap drops idle windows before live ones.
func TestWindowsCapDropsIdleFirst(t *testing.T) {
	s := NewState()
	lim := Limit{Requests: 100, WindowSec: 10, BanSec: 60}
	old := time.Unix(1000, 0)
	for i := 0; i < maxWindows; i++ {
		s.Record(KindAccess, "old"+strconv.Itoa(i), lim, old)
	}
	now := old.Add(time.Minute)
	s.Record(KindAccess, "live", lim, now)
	assert.Len(t, s.windows, 1)
}
