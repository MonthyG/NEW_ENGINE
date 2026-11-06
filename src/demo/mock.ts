// Answers the console's API calls from the demo dataset, in memory. Only the demo build uses it.

import * as D from './data'
import type { Attack, Overview, SiteView } from '../types'

type Res = { status: number; body?: any }
const ok = (body?: any): Res => ({ status: body === undefined ? 204 : 200, body })
const notFound: Res = { status: 404, body: { error: 'not found' } }

// Settings > System state the demo can change: rule set, backups and alerts.
const day = 24 * 3600_000
const ops = {
  ruleset: '',
  backups: [1, 2, 3].map((d) => {
    const t = new Date(D.NOW.getTime() - d * day + 3600_000 * 3)
    return { name: `waf-${t.toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-')}.db`, size: 2_400_000 - d * 41_000, created: t.toISOString() }
  }),
  alerts: { webhook_url: 'https://hooks.slack.com/services/T000/B000/demo', heartbeat_url: '' },
}

const HOUR = 3600_000
let loggedIn = true
let totp = false
const nid = (p: string) => p + '_' + Math.random().toString(16).slice(2, 14).padEnd(12, '0')

function rangeMs(q: URLSearchParams): number {
  const r = q.get('range') || '24h'
  if (r.endsWith('d')) return Number(r.slice(0, -1)) * 24 * HOUR
  if (r.endsWith('h')) return Number(r.slice(0, -1)) * HOUR
  return 24 * HOUR
}

function count<T>(rows: T[], key: (r: T) => string, n = 10, blocked?: (r: T) => number, weight?: (r: T) => number) {
  const m = new Map<string, { key: string; count: number; blocked: number }>()
  for (const r of rows) {
    const k = key(r)
    const v = m.get(k) ?? { key: k, count: 0, blocked: 0 }
    v.count += weight ? weight(r) : 1
    v.blocked += blocked ? blocked(r) : 0
    m.set(k, v)
  }
  return [...m.values()].filter((v) => v.count > 0).sort((a, b) => b.count - a.count).slice(0, n)
}

function overview(q: URLSearchParams): Overview {
  const site = q.get('site') || ''
  const since = D.NOW.getTime() - rangeMs(q)
  const bs = D.buckets.filter((b) => b.t >= since - HOUR + 1 && (!site || b.site === site))
  const sum = (f: (b: D.Bucket) => number) => bs.reduce((n, b) => n + f(b), 0)
  const requests = sum(D.totalOf)
  const blocked = sum((b) => b.block + b.deny + b.rate_limit)
  const step = rangeMs(q) > 2 * 24 * HOUR ? 6 * HOUR : HOUR
  const series = new Map<number, { t: string; requests: number; blocked: number }>()
  for (const b of bs) {
    const t = Math.floor(b.t / step) * step
    const p = series.get(t) ?? { t: new Date(t).toISOString(), requests: 0, blocked: 0 }
    p.requests += D.totalOf(b)
    p.blocked += b.block + b.deny + b.rate_limit
    series.set(t, p)
  }
  const atk = D.attacks.filter((a) => new Date(a.ts).getTime() >= since && (!site || a.site_id === site))
  const actions = [
    ['', sum((b) => b.passed)], ['allow', sum((b) => b.allow)], ['deny', sum((b) => b.deny)], ['rate_limit', sum((b) => b.rate_limit)],
    ['auth', sum((b) => b.auth)], ['wait', sum((b) => b.wait)], ['challenge', sum((b) => b.challenge)], ['block', sum((b) => b.block)],
  ].map(([key, n]) => ({ key: key as string, count: n as number }))
  const bySite = D.sites.map((s) => ({ key: s.id, count: bs.filter((b) => b.site === s.id).reduce((n, b) => n + D.totalOf(b), 0),
    blocked: bs.filter((b) => b.site === s.id).reduce((n, b) => n + b.block + b.deny + b.rate_limit, 0) })).filter((x) => x.count)
  return {
    since: new Date(since).toISOString(), step_sec: step / 1000,
    requests, pv: sum((b) => b.html), uv: Math.round(sum((b) => b.ips) * 0.8), unique_ips: sum((b) => b.ips), blocked,
    blocked_ips: new Set(atk.filter((a) => a.blocked).map((a) => a.client_ip)).size + 6,
    err_4xx: sum((b) => b.err4xx), err_5xx: sum((b) => b.err5xx), blocked_4xx: blocked,
    series: [...series.values()].sort((a, b) => a.t.localeCompare(b.t)), qps: [],
    countries: [], status: [], os: [], browsers: [], referrers: [], pages: [], ips: [],
    sites: bySite.sort((a, b) => b.count - a.count),
    attack_types: count(atk.filter((a) => a.blocked || a.severity <= 2), (a) => a.categories[0]),
    actions,
    rules: ruleHits(atk), p95_ms: requests ? p95(site, requests, sum((b) => b.err5xx)) : 0,
  }
}

/** A believable p95 per site: each origin has its own base speed, and 5xx answers drag it up. */
function p95(site: string, requests: number, err5xx: number) {
  const base = site ? 3 + ([...site].reduce((n, c) => n + c.charCodeAt(0), 0) % 60) : 24
  return Math.round((base + 600 * (err5xx / requests)) * 10) / 10
}

function ruleHits(atk: Attack[]) {
  const m = new Map<string, { id: string; msg: string; category: string; count: number; stopped: number }>()
  for (const a of atk) {
    for (const e of D.matchesByTx[a.tx_id] ?? []) {
      if (!e.rule_id || e.category === 'score') continue
      const v = m.get(e.rule_id) ?? { id: e.rule_id, msg: e.detail, category: e.category ?? '', count: 0, stopped: 0 }
      v.count++
      if (a.blocked) v.stopped++
      m.set(e.rule_id, v)
    }
  }
  return [...m.values()].sort((a, b) => b.count - a.count || a.id.localeCompare(b.id)).slice(0, 8)
}

function siteCounts() {
  const midnight = new Date(D.NOW.getFullYear(), D.NOW.getMonth(), D.NOW.getDate()).getTime()
  const out: Record<string, { requests: number; blocked: number; threats: number }> = {}
  for (const b of D.buckets) {
    if (b.t < midnight) continue
    const v = out[b.site] ?? { requests: 0, blocked: 0, threats: 0 }
    v.requests += D.totalOf(b)
    v.blocked += b.block + b.deny + b.rate_limit
    v.threats += b.block
    out[b.site] = v
  }
  return out
}

function page<T>(rows: T[], q: URLSearchParams) {
  const size = Number(q.get('size') || 20)
  const p = Number(q.get('page') || 1)
  return { items: rows.slice((p - 1) * size, p * size), total: rows.length }
}

function filterAttacks(q: URLSearchParams) {
  const since = q.get('range') ? D.NOW.getTime() - rangeMs(q) : 0
  return D.attacks.filter((a) => (!q.get('site') || a.site_id === q.get('site')) && (!q.get('ip') || a.client_ip === q.get('ip')) &&
    (!q.get('category') || a.categories.includes(q.get('category')!)) && new Date(a.ts).getTime() >= since)
}

function groupRows<T extends { site_id: string; client_ip: string; country: string; ts: string }>(rows: T[]) {
  const m = new Map<string, { site_id: string; client_ip: string; country: string; count: number; first: string; last: string }>()
  for (const r of rows) {
    const k = r.site_id + '|' + r.client_ip
    const g = m.get(k) ?? { site_id: r.site_id, client_ip: r.client_ip, country: r.country, count: 0, first: r.ts, last: r.ts }
    g.count++
    if (r.ts < g.first) g.first = r.ts
    if (r.ts > g.last) g.last = r.ts
    m.set(k, g)
  }
  return [...m.values()].sort((a, b) => b.last.localeCompare(a.last))
}

function patchSite(s: SiteView, patch: Record<string, any>) {
  const r: any = s.resolved
  for (const [k, v] of Object.entries(patch)) {
    if (k === 'auth' && v) r.auth = { ...v, users: (v.users ?? []).map((u: any) => ({ username: u.username })) }
    else if (k === 'ports' && v) r.ports = v
    else if (k === 'upstreams') r.upstreams = v
    else if (k === 'tls') r.tls = { mode: v.mode, cert_id: v.cert_id ?? '' }
    else if (v !== null && typeof v === 'object' && !Array.isArray(v) && r[k] && typeof r[k] === 'object') r[k] = { ...r[k], ...v }
    else r[k] = v
  }
  s.updated = new Date().toISOString()
}

export function demoRequest(method: string, fullPath: string, body: any): Res {
  const [path, query] = fullPath.split('?')
  const q = new URLSearchParams(query)
  const seg = path.split('/').filter(Boolean)
  const key = `${method} /${seg[0] ?? ''}`

  if (path === '/auth/me') return loggedIn ? ok({ username: 'yu-ting', totp_enabled: totp, kind: 'user' }) : { status: 401, body: { error: 'missing or invalid credentials' } }
  if (path === '/auth/login') { loggedIn = true; return ok({ username: body?.username || 'yu-ting', totp_enabled: totp, kind: 'user' }) }
  if (path === '/auth/logout') { loggedIn = false; return ok() }
  if (path === '/auth/password') return ok()
  if (path === '/auth/totp/setup') return ok({ secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP', otpauth_url: 'otpauth://totp/HostingInside%20WAF:yu-ting?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=HostingInside%20WAF' })
  if (path === '/auth/totp/enable') { totp = true; return ok() }
  if (path === '/auth/totp/disable') { totp = false; return ok() }

  if (path === '/protections') return ok([
    ['sqli', 'SQL injection'], ['xss', 'Cross-site scripting'], ['rce', 'Command injection'], ['lfi', 'Path traversal / local file'],
    ['rfi', 'Remote file inclusion'], ['php', 'PHP injection'], ['nodejs', 'Node.js injection'], ['java', 'Java / deserialization'],
    ['session_fixation', 'Session fixation'], ['scanner', 'Scanner / bad-bot detection'], ['protocol', 'Protocol attacks + enforcement'],
    ['data_leak', 'Response data leakage (needs response body inspection)'],
  ].map(([key, label]) => ({ key, label, default: key !== 'data_leak' })))
  if (path === '/apps') return ok([
    ['wordpress', 'WordPress', 'Saving posts and pages in both editors, media, menus, widgets and settings. Comment fields are left to WordPress’s own filter.', ['/wp-admin/', '/wp-json/', '/wp-login.php']],
    ['drupal', 'Drupal', 'Saving content and using the admin forms.', ['/node/', '/admin/structure', '/admin/config']],
    ['nextcloud', 'Nextcloud', 'File sync and uploads (including WebDAV methods), sharing, and editing documents.', ['/remote.php/', '/ocs/', '/index.php/apps/']],
    ['phpmyadmin', 'phpMyAdmin', 'Running SQL from its query box and editing rows.', ['/phpmyadmin/']],
    ['dokuwiki', 'DokuWiki', 'Editing and saving wiki pages.', ['/doku.php', '/lib/exe/']],
    ['phpbb', 'phpBB', 'Posting, private messages and the admin panel.', ['/posting.php', '/ucp.php', '/adm/']],
    ['xenforo', 'XenForo', 'Posting, conversations and the admin panel.', ['/threads/', '/admin.php']],
  ].map(([key, label, summary, paths]) => ({ key, label, summary, paths })))
  if (path === '/system') return ok({ version: '2.0.0', started: new Date(D.NOW.getTime() - 26 * HOUR).toISOString(), engine_ok: true, geoip: true, access_log: true, static_sites: true, http_port: 80, https_port: 443, sites: D.sites.length, ruleset: ops.ruleset ? `CRS ${ops.ruleset}` : 'CRS 4.25.0' })
  if (path === '/site-counts') return ok(siteCounts())
  if (path === '/rulesets' || path === '/rulesets/active') {
    if (method === 'PUT') ops.ruleset = body.version
    const items = ['', '4.30.0'].map((v) => ({ version: v, name: v ? `CRS ${v}` : 'CRS 4.25.0', active: v === ops.ruleset }))
    return ok(method === 'PUT' ? items.find((x) => x.active) : { dir: '/data/rulesets', items })
  }
  if (path === '/backups') {
    if (method === 'POST') {
      const t = new Date()
      const b = { name: `waf-${t.toISOString().slice(0, 19).replace(/[-:]/g, '').replace('T', '-')}.db`, size: 2_480_128, created: t.toISOString() }
      ops.backups.unshift(b)
      return { status: 201, body: b }
    }
    return ok(ops.backups)
  }
  if (path === '/alerts') {
    if (method === 'PUT') Object.assign(ops.alerts, body)
    return ok(ops.alerts)
  }
  if (path === '/alerts/test') return ok({ sent: true })
  if (path === '/stats/overview') return ok(overview(q))
  if (path === '/waitroom') return ok({ [D.S.harbour]: { active: 132, waiting: 0 } })

  if (seg[0] === 'sites') {
    const s = D.sites.find((x) => x.id === seg[1])
    if (method === 'GET' && !seg[1]) return ok(D.sites)
    if (method === 'GET') return s ? ok(s) : notFound
    if (method === 'POST' && !seg[1]) {
      const id = nid('s')
      const ns: SiteView = JSON.parse(JSON.stringify(D.sites[1]))
      ns.id = id
      ns.created = new Date().toISOString()
      ns.resolved.access.rules = []
      ns.resolved.access.block_countries = []
      patchSite(ns, body)
      D.sites.push(ns)
      return ok(ns)
    }
    if (!s) return notFound
    if (method === 'PATCH' || method === 'PUT') { patchSite(s, body); return ok(s) }
    if (method === 'DELETE') { D.sites.splice(D.sites.indexOf(s), 1); return ok() }
    if (seg[2] === 'exclusions') {
      const same = (x: any) => x.rule_id === body.rule_id && x.path_exact === body.path_exact && x.path_prefix === body.path_prefix && x.field === body.field
      if (!s.resolved.exclusions.some(same)) s.resolved.exclusions = [...s.resolved.exclusions, body]
      return ok(s)
    }
    return ok({ files: 12 })
  }

  if (seg[0] === 'attacks' && seg[1] === 'groups') return ok(page(groupRows(filterAttacks(q)), q))
  if (seg[0] === 'attacks' && seg[1]) {
    const a = D.attacks.find((x) => x.tx_id === seg[1])
    if (!a) return notFound
    return ok({ tx_id: a.tx_id, blocked: a.blocked, matches: D.matchesByTx[a.tx_id], request: {
      ts: a.ts, site_id: a.site_id, client_ip: a.client_ip, country: a.country, method: a.method, host: a.host, uri: a.uri, status: a.status,
      bytes: a.blocked ? 1843 : 22410, duration_ms: a.blocked ? 1.4 : 48.2, referer: '',
      user_agent: a.categories[0] === 'scanner' ? 'sqlmap/1.8.4#stable (https://sqlmap.org)' : 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36',
      action: a.blocked ? 'block' : '' } })
  }
  if (seg[0] === 'attacks') return ok(page(filterAttacks(q), q))

  if (seg[0] === 'logs') {
    const types = (q.get('types') || '').split(',').filter(Boolean)
    const rows = D.events.filter((e) => (!types.length || types.includes(e.type)) && (!q.get('site') || e.site_id === q.get('site')) && (!q.get('ip') || e.client_ip === q.get('ip')))
    return ok(seg[1] === 'groups' ? page(groupRows(rows), q) : page(rows, q))
  }

  if (path === '/bans' && method === 'GET') return ok(D.bans)
  if (path === '/bans' && method === 'DELETE') {
    const list = D.bans[q.get('site') || ''] ?? []
    const i = list.findIndex((b) => b.ip === q.get('ip'))
    if (i < 0) return { status: 404, body: { error: 'ip is not banned' } }
    list.splice(i, 1)
    return ok()
  }

  const collections: Record<string, { rows: any[]; prefix: string }> = {
    rules: { rows: D.rules, prefix: 'r' }, 'ip-groups': { rows: D.groups, prefix: 'g' }, certificates: { rows: D.certificates, prefix: 'c' }, tokens: { rows: D.tokens, prefix: 't' },
  }
  const col = collections[seg[0]]
  if (col) {
    if (key === `GET /${seg[0]}`) return ok(col.rows)
    if (method === 'POST') {
      const row = seg[0] === 'certificates'
        ? { id: nid('c'), name: body.name || 'uploaded certificate', subject: body.name, issuer: 'Uploaded', dns_names: [], not_after: new Date(D.NOW.getTime() + 90 * 24 * HOUR).toISOString(), used_by: [], created: new Date().toISOString() }
        : seg[0] === 'tokens' ? { id: nid('t'), name: body.name, created: new Date().toISOString(), token: 'hiw_demo_' + Math.random().toString(36).slice(2) }
        : { ...body, id: nid(col.prefix), updated: new Date().toISOString() }
      col.rows.push(row)
      return ok(row)
    }
    const i = col.rows.findIndex((r) => r.id === seg[1])
    if (i < 0) return notFound
    if (method === 'PUT') { col.rows[i] = { ...col.rows[i], ...body, updated: new Date().toISOString() }; return ok(col.rows[i]) }
    if (method === 'DELETE') { col.rows.splice(i, 1); return ok() }
  }
  return notFound
}
