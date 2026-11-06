export interface Limit { requests: number; window_sec: number; ban_sec: number }
export interface KV { name: string; contains?: string; regex?: string }
export interface Match {
  ip?: string[]; not_ip?: string[]; country?: string[]; method?: string[]
  path_exact?: string; path_prefix?: string; path_regex?: string; host?: string; header?: KV; query?: KV
}
export interface Rule { name?: string; action: 'allow' | 'block'; match: Match }
export interface Port { port: number; https: boolean }
export type Mode = 'block' | 'detect' | 'off'

export interface Resolved {
  name: string; description: string; project: string; type: 'proxy' | 'static' | 'redirect'
  domains: string[]; ports: Port[]; upstreams: string[] | null; lb_policy: string
  redirect: { url: string; code: number; preserve_path: boolean }
  advanced: { hsts: boolean; gzip: boolean; http_redirect: boolean; keep_host: boolean }
  tls: { mode: 'auto' | 'uploaded' | 'off'; cert_id: string }
  waf: { mode: Mode; paranoia: number; anomaly_threshold: number; protections: Record<string, boolean>; apps?: string[] }
  rate_limit: { access: Limit | null; attack: Limit | null; error: Limit | null }
  access: {
    allow_ips: string[] | null; block_ips: string[] | null; allow_countries: string[] | null; block_countries: string[] | null
    block_ips_file: string; allow_groups: string[] | null; block_groups: string[] | null; rules: Rule[] | null
  }
  bot_challenge: { enabled: boolean; difficulty: number }
  auth: { enabled: boolean; users: { username: string }[]; session_ttl_sec: number }
  waiting_room: { enabled: boolean; max_active: number; session_ttl_sec: number }
  block_page: { title: string; message: string }
  exclusions: Exclusion[]
}
export interface Exclusion { rule_id: number; path_exact?: string; path_prefix?: string; field?: string; note?: string }
export interface SiteView { id: string; created: string; updated: string; doc: Record<string, any>; resolved: Resolved }
export interface Protection { key: string; label: string; default: boolean }
// An app profile: CRS's own exclusions for one web application's normal admin and editor traffic.
export interface AppProfile { key: string; label: string; summary: string; paths: string[] }
export interface CountView { key: string; count: number; blocked?: number }
export interface Point { t: string; requests: number; blocked: number }
export interface Overview {
  since: string; step_sec: number
  requests: number; pv: number; uv: number; unique_ips: number; blocked: number; blocked_ips: number
  err_4xx: number; err_5xx: number; blocked_4xx: number
  series: Point[]; qps: Point[]
  countries: CountView[]; status: CountView[]; os: CountView[]; browsers: CountView[]; referrers: CountView[]
  sites: CountView[]; pages: CountView[]; ips: CountView[]; attack_types: CountView[]; actions: CountView[]
  rules: RuleHit[]; p95_ms: number
}
export interface RuleHit { id: string; msg: string; category: string; count: number; stopped: number }
export interface Page<T> { items: T[]; total: number }
export interface Attack {
  tx_id: string; ts: string; site_id: string; client_ip: string; country: string; categories: string[]
  matches: number; severity: number; rule_id: string; msg: string; data: string; blocked: boolean
  method: string; host: string; uri: string; status: number
}
export interface GroupRow { site_id: string; client_ip: string; country: string; count: number; first: string; last: string }
export interface EventRow {
  id: number; ts: string; site_id: string; type: string; client_ip: string; country: string; host: string
  method: string; uri: string; rule_id: string; detail: string; tx_id?: string; data?: string; severity?: number; category?: string
}
export interface AttackDetail {
  tx_id: string; blocked: boolean
  request: { ts: string; site_id: string; client_ip: string; country: string; method: string; host: string; uri: string; status: number; bytes: number; duration_ms: number; user_agent: string; referer: string; action: string } | null
  matches: EventRow[]
}
export interface Certificate { id: string; name: string; subject: string; issuer: string; dns_names: string[] | null; not_after: string; used_by: string[]; created: string }
export interface IPGroup { id: string; name: string; description?: string; ips: string[]; updated: string }
export interface GlobalRule {
  id: string; name: string; enabled: boolean; action: 'allow' | 'block'; sites?: string[]; ip_groups?: string[]; not_ip_groups?: string[]
  match: Match; priority?: number; updated: string
}
export interface Ban { ip: string; until: string }
export interface SystemInfo {
  version: string; started: string; engine_ok: boolean; engine_error?: string; geoip: boolean; access_log: boolean
  static_sites: boolean; http_port: number; https_port: number; sites: number; ruleset?: string
}
export interface Ruleset { version: string; name: string; active: boolean }
export interface Rulesets { dir: string; items: Ruleset[] }
export interface Backup { name: string; size: number; created: string }
export interface Alerts { webhook_url: string; heartbeat_url: string; engine_down_since?: string }
export interface Me { username: string; totp_enabled: boolean; kind: 'user' | 'token'; project?: string }
export interface Token { id: string; name: string; project?: string; created: string; last_used?: string; token?: string }
export type SiteCounts = Record<string, { requests: number; blocked: number; threats: number }>
