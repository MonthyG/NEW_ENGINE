package access

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIPSetIPv6AndMapped(t *testing.T) {
	s, err := ParseIPSet([]string{"203.0.113.0/24", "2001:db8::/32", "198.51.100.7"})
	require.NoError(t, err)
	assert.True(t, s.Contains(netip.MustParseAddr("::ffff:203.0.113.7")))
	assert.True(t, s.Contains(netip.MustParseAddr("2001:db8::1")))
	assert.True(t, s.Contains(netip.MustParseAddr("198.51.100.7")))
	assert.False(t, s.Contains(netip.MustParseAddr("198.51.100.8")))
	_, err = ParseIPSet([]string{"not-an-ip"})
	assert.Error(t, err)
}

func TestIPSetRejectsShortMappedPrefix(t *testing.T) {
	_, err := ParseIPSet([]string{"::ffff:0:0/64"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "::ffff:0:0/64")
	_, err = ParseIPSet([]string{"::ffff:10.0.0.0/104"})
	assert.NoError(t, err)
}
