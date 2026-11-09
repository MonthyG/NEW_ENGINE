// Command hi-waf is the HostingInside WAF engine: Caddy plus Coraza and the
// hi_* modules, built with plain `go build` instead of xcaddy.
package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Caddy standard modules.
	_ "github.com/caddyserver/caddy/v2/modules/standard"
	// Coraza WAF handler (http.handlers.waf).
	_ "github.com/corazawaf/coraza-caddy/v2"

	// HostingInside modules: http.handlers.hi_access, hi_ratelimit,
	// hi_auth, hi_waitroom, hi_challenge, and admin.api.hi_bans.
	_ "hostinginside/waf/engine/access"
	_ "hostinginside/waf/engine/auth"
	_ "hostinginside/waf/engine/challenge"
	_ "hostinginside/waf/engine/ratelimit"
	_ "hostinginside/waf/engine/waitroom"
)

func main() {
	caddycmd.Main()
}
