package compile

import (
	"html"
	"strings"

	"hostinginside/waf/manager/site"
)

// blockPageTmpl is the page served for WAF errors. %TITLE%, %MSG%, %ICON%
// and %COLOR% are replaced at compile time (customer text is escaped); the
// {http.error.*} placeholders are expanded by Caddy per request.
const blockPageTmpl = `<!doctype html><html lang="en"><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1"><title>%TITLE%</title>` +
	`<style>body{margin:0;font:15px system-ui,-apple-system,"Segoe UI",sans-serif;background:#f3f6f8;color:#1d2b36;` +
	`display:flex;min-height:100vh;align-items:center;justify-content:center}` +
	`.c{background:#fff;border-radius:12px;box-shadow:0 8px 30px rgba(0,0,0,.07);padding:40px 44px;max-width:460px;text-align:center}` +
	`.i{width:72px;height:72px;border-radius:50%;margin:0 auto 18px;display:flex;align-items:center;justify-content:center;background:%COLOR%1a}` +
	`h1{font-size:21px;margin:0 0 10px}p{color:#5c6b77;margin:0 0 6px;line-height:1.5}` +
	`.m{margin-top:22px;padding-top:16px;border-top:1px solid #eef1f3;font-size:12px;color:#9aa7b1}` +
	`code{font-family:ui-monospace,Consolas,monospace;color:#5c6b77}</style></head><body><div class="c">` +
	`<div class="i">%ICON%</div><h1>%TITLE%</h1><p>%MSG%</p>` +
	`<div class="m">Status <code>{http.error.status_code}</code> &middot; Event ID <code>{http.error.id}</code>` +
	`<br>Protected by HostingInside WAF</div></div></body></html>`

const shieldIcon = `<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#e5484d" stroke-width="2"` +
	` stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>` +
	`<line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>`

const clockIcon = `<svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#f59e0b" stroke-width="2"` +
	` stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>`

func renderPage(title, msg, icon, color string) string {
	return strings.NewReplacer(
		"%TITLE%", pageText(title), "%MSG%", pageText(msg), "%ICON%", icon, "%COLOR%", color,
	).Replace(blockPageTmpl)
}

func pageHandler(body string) map[string]any {
	return map[string]any{
		"handler":     "static_response",
		"status_code": "{http.error.status_code}",
		"headers": map[string]any{
			"Content-Type":  []string{"text/html; charset=utf-8"},
			"Cache-Control": []string{"no-store"},
		},
		"body": body,
	}
}

// blockPages returns the site's error routes: a rate-limit page for 429 and
// the site's block page for everything else. match nil means any host.
func blockPages(s site.Resolved, match []any) []any {
	tooMany := map[string]any{"expression": "{http.error.status_code} == 429"}
	var m429 []any
	if match != nil {
		host := match[0].(map[string]any)
		m429 = []any{map[string]any{"host": host["host"], "expression": tooMany["expression"]}}
	} else {
		m429 = []any{tooMany}
	}
	rate := map[string]any{
		"match": m429,
		"handle": []any{pageHandler(renderPage("Too many requests",
			"You are sending requests too fast. Please wait a moment and try again.", clockIcon, "#f59e0b"))},
		"terminal": true,
	}
	block := map[string]any{
		"handle": []any{pageHandler(renderPage(s.BlockTitle, s.BlockMessage, shieldIcon, "#e5484d"))},
	}
	if match != nil {
		block["match"] = match
	}
	return []any{rate, block}
}

// pageText HTML-escapes customer text and turns braces into entities so Caddy
// doesn't expand placeholders like {env.SECRET} inside it.
func pageText(s string) string {
	return strings.NewReplacer("{", "&#123;", "}", "&#125;").Replace(html.EscapeString(s))
}
