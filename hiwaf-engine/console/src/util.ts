import type { SiteView } from './types'

const regions = new Intl.DisplayNames(['en'], { type: 'region' })
export function countryName(code: string | undefined): string {
  if (!code) return 'Unknown location'
  try {
    return regions.of(code.toUpperCase()) ?? code
  } catch {
    return code
  }
}

const nf = new Intl.NumberFormat('en')
export const int = (n: number | undefined) => (n === undefined || n === null ? '—' : nf.format(n))
export function compact(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'm'
  if (n >= 10_000) return (n / 1000).toFixed(n >= 100_000 ? 0 : 1).replace(/\.0$/, '') + 'k'
  return nf.format(n)
}
export function pct(part: number, whole: number, digits = 1): string {
  if (!whole) return '0%'
  return ((part / whole) * 100).toFixed(digits) + '%'
}

const pad = (n: number) => String(n).padStart(2, '0')
export function clock(iso: string | Date): string {
  const d = typeof iso === 'string' ? new Date(iso) : iso
  return `${pad(d.getHours())}:${pad(d.getMinutes())}`
}
export function dateTime(iso: string | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`
}
/** "Today 14:02", "Yesterday 23:10", "2026-10-21 09:00". */
export function when(iso: string | undefined, now = new Date()): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const day = (x: Date) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime()
  const diff = (day(now) - day(d)) / 86400000
  if (diff === 0) return `Today ${clock(d)}`
  if (diff === 1) return `Yesterday ${clock(d)}`
  return dateTime(iso)
}
export function ago(iso: string, now = new Date()): string {
  const s = Math.max(0, Math.round((now.getTime() - new Date(iso).getTime()) / 1000))
  if (s < 60) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m} min ago`
  const h = Math.round(m / 60)
  if (h < 48) return `${h} h ago`
  return `${Math.round(h / 24)} days ago`
}
export function span(fromIso: string, toIso: string): string {
  const m = Math.round((new Date(toIso).getTime() - new Date(fromIso).getTime()) / 60000)
  if (m < 1) return 'under a minute'
  if (m < 60) return `${m} min`
  const h = Math.floor(m / 60)
  return m % 60 ? `${h} h ${m % 60} min` : `${h} h`
}
export function seconds(sec: number): string {
  if (sec % 86400 === 0) return `${sec / 86400} d`
  if (sec % 3600 === 0) return `${sec / 3600} h`
  if (sec % 60 === 0) return `${sec / 60} min`
  return `${sec} s`
}
export function daysLeft(iso: string, now = new Date()): number {
  return Math.floor((new Date(iso).getTime() - now.getTime()) / 86400000)
}

export const categoryLabels: Record<string, string> = {
  sqli: 'SQL injection', xss: 'Cross-site scripting', rce: 'Command injection', lfi: 'Path traversal',
  rfi: 'Remote file inclusion', php: 'PHP injection', nodejs: 'Node.js injection', java: 'Java and deserialization',
  session_fixation: 'Session fixation', scanner: 'Scanner', protocol: 'Protocol abuse', data_leak: 'Data leak', '': 'Other rule',
}
export const categoryLabel = (c: string) => categoryLabels[c] ?? c

/** Our words for the engine's event types. */
export const eventLabels: Record<string, string> = {
  waf_block: 'Threat stopped', waf_match: 'Threat seen', rate_limit_ban: 'Banned by rate limit',
  ip_block: 'Refused: IP list', geo_block: 'Refused: country', rule_block: 'Refused: rule', allowed_by_rule: 'Let through by rule',
  challenge_passed: 'Bot check passed', challenge_failed: 'Bot check failed',
  auth_passed: 'Signed in at gate', auth_failed: 'Wrong gate password',
}
export const modeWord: Record<string, string> = { block: 'Block', detect: 'Watch', off: 'Off' }

export function siteName(s: SiteView | undefined, fallback = ''): string {
  if (!s) return fallback
  return s.resolved.name || s.resolved.domains.map((d) => (d === '*' ? 'Any host' : d)).join(', ')
}
export function siteHosts(s: SiteView): string {
  return s.resolved.domains.map((d) => (d === '*' ? 'any host' : d)).join(', ')
}
