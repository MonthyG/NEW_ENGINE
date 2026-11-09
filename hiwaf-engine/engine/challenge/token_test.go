package challenge

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSite = "s_aabbccddeeff"

var testKey = []byte("0123456789abcdef0123456789abcdef")

func TestSafeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/shop?a=1":        "/shop?a=1",
		"":                 "/",
		"//evil.com":       "/",
		"/\\evil.com":      "/",
		"https://evil.com": "/",
		"shop":             "/",
		"/a\r\nX: y":       "/",
	} {
		assert.Equal(t, want, safeReturn(in), in)
	}
}

func TestTokenBoundToIPAndExpires(t *testing.T) {
	t0 := time.Unix(1_700_000_000, 0)
	tok := issueToken(testKey, testSite, "1.1.1.1", t0)
	assert.NoError(t, checkToken(testKey, tok, testSite, "1.1.1.1", t0))
	assert.NoError(t, checkToken(testKey, tok, testSite, "1.1.1.1", t0.Add(119*time.Second)))
	assert.Error(t, checkToken(testKey, tok, testSite, "2.2.2.2", t0))
	assert.Error(t, checkToken(testKey, tok, "s_000000000000", "1.1.1.1", t0))
	assert.Error(t, checkToken(testKey, tok, testSite, "1.1.1.1", t0.Add(121*time.Second)))
	assert.Error(t, checkToken([]byte("another-key-another-key-another-"), tok, testSite, "1.1.1.1", t0))

	payload, mac, _ := strings.Cut(tok, ".")
	assert.Error(t, checkToken(testKey, payload+"x."+mac, testSite, "1.1.1.1", t0))
	assert.Error(t, checkToken(testKey, payload+"."+mac+"x", testSite, "1.1.1.1", t0))
	assert.Error(t, checkToken(testKey, payload, testSite, "1.1.1.1", t0))
	assert.Error(t, checkToken(testKey, "", testSite, "1.1.1.1", t0))
}

// solve brute-forces a nonce that satisfies validPoW.
func solve(tok string, difficulty int) string {
	for i := 0; ; i++ {
		if n := strconv.Itoa(i); validPoW(tok, n, difficulty) {
			return n
		}
	}
}

func TestValidPoW(t *testing.T) {
	tok := "some.token"
	n := solve(tok, 2)
	assert.True(t, validPoW(tok, n, 2))
	assert.True(t, validPoW(tok, n, 1))
	assert.False(t, validPoW(tok, n, 64)) // not 64 leading zeros

	// find a nonce whose hash lacks the "00" prefix
	for i := 0; ; i++ {
		if m := strconv.Itoa(i); !validPoW(tok, m, 2) {
			assert.False(t, validPoW(tok, m, 2))
			break
		}
	}
}

func TestClearanceBoundToSiteAndIP(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	exp := now.Add(time.Hour)
	c := makeClearance(testKey, testSite, "1.1.1.1", exp)
	assert.True(t, checkClearance(testKey, c, testSite, "1.1.1.1", now))
	assert.False(t, checkClearance(testKey, c, testSite, "2.2.2.2", now))
	assert.False(t, checkClearance(testKey, c, "s_000000000000", "1.1.1.1", now))
	assert.False(t, checkClearance(testKey, c, testSite, "1.1.1.1", exp))
	assert.False(t, checkClearance(testKey, "garbage", testSite, "1.1.1.1", now))
	// exp tampering invalidates the MAC
	_, m, _ := strings.Cut(c, ".")
	assert.False(t, checkClearance(testKey, strconv.FormatInt(exp.Unix()+999, 10)+"."+m, testSite, "1.1.1.1", now))
	// a challenge token is not a clearance cookie
	tok := issueToken(testKey, testSite, "1.1.1.1", now)
	assert.False(t, checkClearance(testKey, tok, testSite, "1.1.1.1", now))
}

func TestValidate(t *testing.T) {
	good := func() *Challenge {
		c := &Challenge{SiteID: testSite, Secret: "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="}
		require.NoError(t, c.setup())
		return c
	}
	c := good()
	assert.Equal(t, 4, c.Difficulty)
	assert.Equal(t, 3600, c.ClearanceTTLSec)
	assert.NoError(t, c.Validate())

	c = good()
	c.Difficulty = 7
	assert.Error(t, c.Validate())

	c = &Challenge{SiteID: testSite, Secret: "c2hvcnQ="}
	require.NoError(t, c.setup())
	assert.Error(t, c.Validate())

	c = &Challenge{SiteID: testSite, Secret: "!!!"}
	assert.Error(t, c.setup())
}
