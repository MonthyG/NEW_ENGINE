package clientip_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/stretchr/testify/assert"

	"hostinginside/waf/engine/clientip"
)

func TestClientIPIgnoresXFFWithoutTrustedProxy(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "198.51.100.9:5555"
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	assert.Equal(t, "198.51.100.9", clientip.Get(r))
}

func TestClientIPUnmapsAndPrefersCaddyVar(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r = r.WithContext(context.WithValue(r.Context(), caddyhttp.VarsCtxKey, map[string]any{caddyhttp.ClientIPVarKey: "::ffff:203.0.113.7"}))
	assert.Equal(t, "203.0.113.7", clientip.Get(r))
}

func TestClientIPUnmapsRemoteAddr(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "[::ffff:192.0.2.1]:80"
	assert.Equal(t, "192.0.2.1", clientip.Get(r))
}
