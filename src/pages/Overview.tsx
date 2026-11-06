import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { Attack, Ban, GroupRow, Overview as Ov, Page, SiteCounts, Certificate } from '../types'
import { Btn, Empty, ModePill, useInterval } from '../ui'
import { ago, categoryLabel, clock, countryName, daysLeft, int, pct, siteName, when } from '../util'
import { Flow, Radar } from './live'

type Range = '1h' | '24h' | '7d' | '30d'
const ranges: Range[] = ['1h', '24h', '7d', '30d']
const rangeWords: Record<Range, string> = { '1h': 'hour', '24h': '24 hours', '7d': '7 days', '30d': '30 days' }

/** Draws one chart into a div whenever its inputs change. */
export function ChartBox({ draw, deps, height, label }: { draw: (el: HTMLDivElement) => void; deps: unknown[]; height?: number; label: string }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) draw(ref.current)
    // charts read their colours from the theme when drawn, so a theme switch redraws them
    const redraw = () => { if (ref.current) draw(ref.current) }
    window.addEventListener('themechange', redraw)
    return () => window.removeEventListener('themechange', redraw)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return <div ref={ref} className="chart" style={{ minHeight: height }} aria-label={label} />
}

const stages: { key: string; name: string; note: (n: number) => string }[] = [
  { key: 'deny', name: 'Access rules', note: () => 'refused by IP, country or rule' },
  { key: 'rate_limit', name: 'Rate limits', note: () => 'from banned sources' },
  { key: 'auth', name: 'Password gate', note: (n) => (n ? 'sign-in pages shown' : 'no gate was hit') },
  { key: 'wait', name: 'Queue', note: (n) => (n ? 'visitors held in line' : 'nobody had to wait') },
  { key: 'challenge', name: 'Bot check', note: () => 'challenge pages shown' },
  { key: 'block', name: 'Threat inspection', note: () => 'stopped by the rule set' },
]

// Coraza severities: 0 emergency, 1 alert, 2 critical, 3 error, 4 warning, 5 notice
const sevClass = (n: number) => (n <= 2 ? 'crit' : n === 3 ? 'high' : n === 4 ? 'med' : 'low')
const sevWord = (n: number) => (n <= 2 ? 'critical' : n === 3 ? 'error' : n === 4 ? 'warning' : 'notice')

/** The request line with the part that matched a rule marked. */
function RequestLine({ a }: { a: Attack }) {
  const line = `${a.method || 'GET'} ${a.uri}`
  let decoded = line
  try { decoded = decodeURIComponent(line) } catch { /* keep it encoded */ }
  for (const text of [line, decoded]) {
    const i = a.data && a.data.length > 2 ? text.indexOf(a.data) : -1
    if (i >= 0) return <>{text.slice(0, i)}<em>{a.data}</em>{text.slice(i + a.data.length)}</>
  }
  return <>{line}</>
}

/** Ticks once a second on its own so the page around it stays still. */
function Clock() {
  const [t, setT] = useState(() => new Date())
  useInterval(useCallback(() => setT(new Date()), []), 1000)
  return <span>{t.toISOString().slice(0, 19).replace('T', ' ')} UTC</span>
}

export default function Overview() {
  const { sites, siteById, system, notify, notifyError } = useApp()
  const navigate = useNavigate()
  const [range, setRange] = useState<Range>('24h')
  const [site, setSite] = useState('')
  const [streaming, setStreaming] = useState(true)
  const [ov, setOv] = useState<Ov | null>(null)
  const [sources, setSources] = useState<GroupRow[]>([])
  const [bans, setBans] = useState<Record<string, Ban[]>>({})
  const [counts, setCounts] = useState<SiteCounts>({})
  const [certs, setCerts] = useState<Certificate[]>([])
  const [attacks, setAttacks] = useState<Attack[]>([])
  const [fresh, setFresh] = useState<Set<string>>(new Set())
  const [stamp, setStamp] = useState<Date | null>(null)
  const seen = useRef<Set<string> | null>(null)

  const load = useCallback(() => {
    Promise.all([
      api.get<Ov>('/stats/overview' + qs({ range, site })),
      api.get<Page<GroupRow>>('/attacks/groups' + qs({ range, site, size: 50 })),
      api.get<Record<string, Ban[]>>('/bans').catch(() => ({})),
      api.get<SiteCounts>('/site-counts'),
      api.get<Certificate[]>('/certificates'),
      api.get<Page<Attack>>('/attacks' + qs({ range, site, size: 200 })),
    ]).then(([o, g, b, c, ce, a]) => {
      setOv(o); setSources(g.items); setBans(b); setCounts(c); setCerts(ce); setAttacks(a.items)
      // rows that arrived since the last load flash once; the first load marks nothing
      const ids = new Set(a.items.map((x) => x.tx_id))
      setFresh(seen.current ? new Set([...ids].filter((id) => !seen.current!.has(id))) : new Set())
      seen.current = ids
      setStamp(new Date())
    }).catch(notifyError)
  }, [range, site, notifyError])
  useEffect(() => { seen.current = null; load() }, [load])
  useInterval(load, streaming ? 10_000 : 0)

  const act = useMemo(() => Object.fromEntries((ov?.actions ?? []).map((a) => [a.key, a.count])), [ov])
  const requests = ov?.requests ?? 0
  const held = stages.reduce((n, s) => n + (act[s.key] ?? 0), 0)
  const reached = requests - held
  const watched = attacks.filter((x) => !x.blocked).length

  const watchSites = new Set(sites.filter((s) => s.resolved.waf.mode === 'detect').map((s) => s.id))
  // ranked by how much each source sent; a source let through in Watch never leads the finding
  const ranked = [...sources].sort((a, b) => b.count - a.count || b.last.localeCompare(a.last))
  const top = ranked.find((g) => !watchSites.has(g.site_id))
  const topBan = top ? (bans[top.site_id] ?? []).find((b) => b.ip === top.client_ip) : undefined
  const refuse = async (ip: string) => {
    try {
      await api.post('/rules', { name: `Refuse ${ip}`, enabled: true, action: 'block', sites: [], match: { ip: [ip] }, priority: 0 })
      notify(`${ip} is now refused on every site`)
    } catch (e) {
      notifyError(e)
    }
  }

  const finding = top
    ? <>{top.client_ip} ({countryName(top.country)}) sent <strong>{top.count} attacks</strong> to {siteName(siteById[top.site_id], top.site_id)} {top.count > 1 ? <>between {clock(top.first)} and {clock(top.last)}</> : <>at {clock(top.last)}</>}{topBan ? <>; it is banned until {clock(topBan.until)}</> : null}.</>
    : <>No threats in the last {rangeWords[range]}.</>

  // the newest source on a blocking site decides the status line: under attack within 15 minutes
  const newest = [...sources].filter((g) => !watchSites.has(g.site_id)).sort((a, b) => b.last.localeCompare(a.last))[0]
  const active = newest && Date.now() - new Date(newest.last).getTime() < 15 * 60_000 ? newest : undefined
  const status = !ov ? null : active ? (
    <p className="alert-line" role="status"><span className="beacon" aria-hidden="true" />
      Under attack: {active.client_ip} is hitting {siteName(siteById[active.site_id], active.site_id)}, last {ago(active.last)}</p>
  ) : (
    <p className="alert-line calm" role="status"><span className="beacon" aria-hidden="true" />
      {newest ? `Quiet: the last stopped threat was ${ago(newest.last)}` : 'Quiet: nothing has been stopped in this window'}</p>
  )

  // what needs a decision, most urgent first
  const banRows = Object.entries(bans).flatMap(([s, list]) => list.map((b) => ({ site: s, ...b })))
  type Decision = { lvl: 'crit' | 'mod' | 'low'; text: React.ReactNode; why: string; to?: string; action: string; run?: () => void }
  const decisions: Decision[] = []
  if (active) decisions.push({ lvl: 'crit', text: <><strong>{active.client_ip}</strong> is attacking {siteName(siteById[active.site_id], active.site_id)} now</>, why: `${active.count} attacks, last ${ago(active.last)}`, action: 'Refuse', run: () => refuse(active.client_ip) })
  for (const c of certs) {
    const d = daysLeft(c.not_after)
    if (d <= 21) decisions.push({ lvl: d <= 7 ? 'crit' : 'mod', text: <>Certificate for <strong>{c.dns_names?.[0] ?? c.name}</strong> expires in {d} days</>, why: `used by ${c.used_by.length || 'no'} site${c.used_by.length === 1 ? '' : 's'}`, to: '/settings/certificates', action: 'Replace' })
  }
  for (const s of sites) {
    if (s.resolved.waf.mode === 'detect') decisions.push({ lvl: 'mod', text: <><strong>{siteName(s)}</strong> is in Watch</>, why: 'threats are logged and let through', to: `/threats?site=${s.id}`, action: 'Review' })
  }
  for (const b of banRows) {
    decisions.push({ lvl: 'low', text: <><strong>{b.ip}</strong> is banned on {siteName(siteById[b.site], b.site)}</>, why: `until ${clock(b.until)}`, to: '/access?tab=bans', action: 'Bans' })
  }
  const order = { crit: 0, mod: 1, low: 2 }
  const lvlWord = { crit: 'Urgent', mod: 'Soon', low: 'Note' }
  decisions.sort((a, b) => order[a.lvl] - order[b.lvl])

  const last = ov?.series[ov.series.length - 1]
  const perSecond = last && ov ? last.requests / Math.max(1, ov.step_sec) : 0

  const chartDraw = (el: HTMLDivElement) => {
    if (!ov) return
    const step = ov.step_sec
    const labels = ov.series.map((p) => {
      const d = new Date(p.t)
      return step >= 6 * 3600 ? `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}h` : clock(d)
    })
    const res = window.Charts.line(el, {
      labels, height: 300, format: window.Charts.fmt.int,
      series: [
        { name: 'Requests', values: ov.series.map((p) => p.requests) },
        { name: 'Stopped', values: ov.series.map((p) => p.blocked) },
      ],
    })
    const legendSlot = el.parentElement?.querySelector('.legend-slot')
    if (legendSlot && res && res.legend) { legendSlot.innerHTML = ''; legendSlot.appendChild(res.legend) }
  }

  const typeDraw = (el: HTMLDivElement) => {
    const rows = (ov?.attack_types ?? []).map((c) => ({ label: categoryLabel(c.key), value: c.count }))
    if (!rows.length) { el.innerHTML = ''; return }
    window.Charts.barList(el, rows, { thin: true })
  }

  const ordered = [...sites].sort((a, b) => (counts[b.id]?.requests ?? 0) - (counts[a.id]?.requests ?? 0)).slice(0, 5)
  const rules = ov?.rules ?? []
  const topHits = rules[0]?.count ?? 0
  const stream = [...attacks].sort((a, b) => b.ts.localeCompare(a.ts)).slice(0, 12)
  const blocked = ov?.blocked ?? 0

  return (
    <>
      <div className="title-row">
        <div>
          <h1>Overview</h1>
          <p className="sub">{finding}</p>
          {status}
        </div>
        {top && <div className="actions"><Btn onClick={() => refuse(top.client_ip)}>Refuse {top.client_ip} everywhere</Btn></div>}
      </div>

      <div className="query" role="search" aria-label="What the overview shows">
        <div className="q-in">
          <span className="prompt" aria-hidden="true">&gt;</span>
          <label className="chip"><i>site:</i>
            <select value={site} onChange={(e) => setSite(e.target.value)} aria-label="Site">
              <option value="">all</option>
              {sites.map((s) => <option key={s.id} value={s.id}>{siteName(s)}</option>)}
            </select>
            {site && <button type="button" aria-label="Show every site" onClick={() => setSite('')}>×</button>}
          </label>
          <span className="chip"><i>window:</i>{range}</span>
          <span className="stamp muted">{stamp ? `updated ${clock(stamp)}` : 'loading'}</span>
        </div>
        <div className="range" role="group" aria-label="Time window">
          {ranges.map((r) => <button key={r} type="button" aria-pressed={range === r} onClick={() => setRange(r)}>{r}</button>)}
        </div>
        <button type="button" className="stream" aria-pressed={streaming} onClick={() => setStreaming(!streaming)}
          title={streaming ? 'Refreshing every 10 seconds; click to pause' : 'Paused; click to refresh every 10 seconds'}>
          <span className="sq" aria-hidden="true" />{streaming ? 'streaming' : 'paused'}
        </button>
      </div>

      <div className="sheet">
        <div className="kpis five span-12">
          <div className="kpi">
            <div className="kpi-label">Requests inspected</div>
            <div className="kpi-value big">{int(requests)}</div>
            <div className="note">{ov ? `${int(ov.unique_ips)} client IPs` : ''}</div>
          </div>
          <div className="kpi lead">
            <div className="kpi-label">Stopped</div>
            <div className="kpi-value big">{int(blocked)}</div>
            <div className="note">{pct(blocked, requests)} of requests</div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Challenged</div>
            <div className="kpi-value big">{int(act.challenge ?? 0)}</div>
            <div className="note">bot checks shown</div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Attacking IPs</div>
            <div className="kpi-value big">{int(ov?.blocked_ips ?? 0)}</div>
            <div className="note">stopped at least once</div>
          </div>
          <div className="kpi">
            <div className="kpi-label">Request time, p95</div>
            <div className="kpi-value big">{ov && requests ? (ov.p95_ms < 10 ? ov.p95_ms.toFixed(1) : int(Math.round(ov.p95_ms))) : '-'}<small>ms</small></div>
            <div className="note">through the edge</div>
          </div>
        </div>

        <section className="panel span-12" aria-labelledby="cp-title">
          <header>
            <h2 id="cp-title">Where requests stopped</h2>
            <span className="meta">Each request passes the stages left to right; the first one that refuses it ends its trip.</span>
          </header>
          <Flow requests={requests} stops={act} perSecond={perSecond} />
          <div className="checkpoints">
            <div className="cp">
              <div className="cp-name">Requests in</div>
              <div className="cp-value lead num">{int(requests)}</div>
              <div className="cp-bar ink"><span style={{ width: '100%' }} /></div>
              <div className="cp-note">{ov ? `${int(ov.unique_ips)} client IPs` : ''}</div>
            </div>
            {stages.map((s) => {
              const n = act[s.key] ?? 0
              return (
                <div key={s.key} className={'cp' + (n ? '' : ' off')}>
                  <div className="cp-name" title={s.name}>{s.name}</div>
                  <div className="cp-value num">{int(n)}</div>
                  <div className="cp-bar"><span style={{ width: requests ? `${Math.max(n ? 2 : 0, (n / requests) * 100)}%` : 0 }} /></div>
                  <div className="cp-note">{s.key === 'block' && watched ? `${s.note(n)}; ${watched} more watched` : s.note(n)}</div>
                </div>
              )
            })}
            <div className="cp">
              <div className="cp-name">Reached the origin</div>
              <div className="cp-value lead num">{int(reached)}</div>
              <div className="cp-bar ink"><span style={{ width: requests ? `${(reached / requests) * 100}%` : 0 }} /></div>
              <div className="cp-note">{pct(reached, requests)} of requests{act.allow ? `, ${int(act.allow)} by allow rule` : ''}</div>
            </div>
          </div>
        </section>

        <section className="panel span-6" aria-labelledby="tr-title">
          <header>
            <h2 id="tr-title">Requests and stops</h2>
            <div className="legend-slot meta" />
          </header>
          <ChartBox label="Requests and stopped requests over time" draw={chartDraw} deps={[ov]} height={300} />
        </section>

        <section className="panel span-6" aria-labelledby="src-title">
          <header>
            <h2 id="src-title">Threat sources</h2>
            <Link className="card-link" to="/threats">All threats</Link>
          </header>
          {ranked.length ? (
            <div className="radar-panel">
              <Radar sources={ranked} watchSites={watchSites} />
              <div className="rows">
                {ranked.slice(0, 5).map((g) => (
                  <button key={g.site_id + g.client_ip} type="button" className="row" onClick={() => navigate(`/threats?ip=${g.client_ip}&site=${g.site_id}`)}
                    style={{ width: '100%', border: 0, background: 'none', textAlign: 'left', cursor: 'pointer', padding: '8px 0' }}>
                    <span className="mode-dot" style={{ background: watchSites.has(g.site_id) ? 'var(--warning)' : 'var(--negative)', flex: 'none' }} aria-hidden="true" />
                    <span className="grow">
                      <span className="num" style={{ display: 'block', fontWeight: 600 }}><span className="flag">{g.country || '--'}</span>{g.client_ip}</span>
                      <span className="meta truncate" style={{ display: 'block' }}>{countryName(g.country)} · {siteName(siteById[g.site_id], g.site_id)}</span>
                    </span>
                    <span style={{ textAlign: 'right' }}>
                      <span className="num" style={{ display: 'block', fontWeight: 500 }}>{g.count}</span>
                      <span className="meta" style={{ display: 'block', whiteSpace: 'nowrap' }}>{when(g.last)}</span>
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ) : <Empty>No threats in this window.</Empty>}
        </section>

        <section className="panel span-7 flush" aria-labelledby="sites-title">
          <header>
            <h2 id="sites-title">Sites today</h2>
            <Link className="card-link" to="/sites">All {sites.length} sites</Link>
          </header>
          <div className="table-wrap" style={{ marginTop: 4 }}>
            <table className="responsive">
              <thead>
                <tr><th>Site</th><th>Mode</th><th className="n">Requests</th><th className="n">Stopped</th><th className="n hide-phone">Stop rate</th></tr>
              </thead>
              <tbody>
                {ordered.map((s) => {
                  const c = counts[s.id]
                  return (
                    <tr key={s.id} className="clickable" onClick={() => navigate(`/sites/${s.id}`)}>
                      <td><span className="ident">{siteName(s)}</span><span className="sub truncate">{s.resolved.domains.join(', ')}</span></td>
                      <td><ModePill mode={s.resolved.waf.mode} /></td>
                      <td className="n num">{int(c?.requests ?? 0)}</td>
                      <td className="n num">{int(c?.blocked ?? 0)}</td>
                      <td className="n num hide-phone">{pct(c?.blocked ?? 0, c?.requests ?? 0)}</td>
                    </tr>
                  )
                })}
              </tbody>
              <tfoot>
                <tr>
                  <td className="muted">All {sites.length} sites</td><td />
                  <td className="n num">{int(sites.reduce((n, s) => n + (counts[s.id]?.requests ?? 0), 0))}</td>
                  <td className="n num">{int(sites.reduce((n, s) => n + (counts[s.id]?.blocked ?? 0), 0))}</td>
                  <td className="hide-phone" />
                </tr>
              </tfoot>
            </table>
          </div>
        </section>

        <section className="panel span-5 flush" aria-labelledby="att-title">
          <header><h2 id="att-title">Needs a decision</h2><span className="meta num">{decisions.length}</span></header>
          {decisions.length ? (
            <ul className="queue" style={{ marginTop: 10 }}>
              {decisions.map((d, i) => (
                <li key={i}>
                  <span className={'lvl ' + d.lvl}>{lvlWord[d.lvl]}</span>
                  <div>{d.text}<small>{d.why}</small></div>
                  {d.run ? <button type="button" className="mini-btn" onClick={d.run}>{d.action}</button> : <Link className="card-link" to={d.to!}>{d.action}</Link>}
                </li>
              ))}
            </ul>
          ) : <div style={{ padding: 'var(--card-pad)' }}><Empty>Nothing needs you right now.</Empty></div>}
        </section>

        <section className="panel span-7 flush" aria-labelledby="rules-title">
          <header><h2 id="rules-title">Rules hit most</h2><span className="meta">last {rangeWords[range]}</span></header>
          {rules.length ? (
            <div className="table-wrap" style={{ marginTop: 4 }}>
              <table className="responsive rules">
                <thead><tr><th>Rule</th><th>What it catches</th><th className="hide-phone">Kind</th><th className="n">Matches</th><th className="n hide-phone">Watched</th></tr></thead>
                <tbody>
                  {rules.map((r) => (
                    <tr key={r.id}>
                      <td className="num">{r.id}</td>
                      <td className="secondary"><span className="truncate" style={{ display: 'block', maxWidth: 340 }} title={r.msg}>{r.msg}</span></td>
                      <td className="muted hide-phone">{categoryLabel(r.category)}</td>
                      <td className="n num"><span className="meter hide-phone" aria-hidden="true"><i style={{ width: `${topHits ? (r.count / topHits) * 100 : 0}%` }} /></span>{int(r.count)}</td>
                      <td className={'n num hide-phone' + (r.count > r.stopped ? ' warn-text' : ' muted')} title="Matched on a site in Watch mode, so let through">{int(r.count - r.stopped)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div style={{ padding: 'var(--card-pad)' }}><Empty>No rule matched in this window.</Empty></div>}
        </section>

        <section className="panel span-5" aria-labelledby="types-title">
          <header><h2 id="types-title">What the threats tried</h2><span className="meta">last {rangeWords[range]}</span></header>
          {(ov?.attack_types ?? []).length ? <ChartBox label="Threats by kind" draw={typeDraw} deps={[ov]} /> : <Empty>No threats in this window.</Empty>}
        </section>

        <section className="panel span-12 flush" aria-labelledby="ev-title">
          <header>
            <h2 id="ev-title">Threat stream</h2>
            <span className="meta">{streaming ? 'newest first, refreshed every 10 seconds' : 'paused'} · <Link className="card-link" to="/threats">Open threats</Link></span>
          </header>
          {stream.length ? (
            <div className="table-wrap" style={{ marginTop: 4 }}>
              <table className="events">
                <thead>
                  <tr><th>Time</th><th>Verdict</th><th>Source</th><th className="hide-phone">Site</th><th>Request</th><th className="hide-phone">Rule</th><th className="hide-phone">Severity</th></tr>
                </thead>
                <tbody>
                  {stream.map((a) => (
                    <tr key={a.tx_id} className={'clickable' + (fresh.has(a.tx_id) ? ' fresh' : '')} onClick={() => navigate(`/threats?ip=${a.client_ip}&site=${a.site_id}`)}>
                      <td className="muted">{clock(a.ts)}</td>
                      <td><span className={'verdict ' + (a.blocked ? 'deny' : 'log')}>{a.blocked ? 'STOP' : 'WATCH'}</span></td>
                      <td><span className="flag">{a.country || '--'}</span>{a.client_ip}</td>
                      <td className="hide-phone">{siteName(siteById[a.site_id], a.site_id)}</td>
                      <td className="req" title={`${a.method} ${a.uri}`}><RequestLine a={a} /></td>
                      <td className="hide-phone muted">{a.rule_id}</td>
                      <td className="hide-phone"><span className={'sev ' + sevClass(a.severity)}>{sevWord(a.severity)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : <div style={{ padding: 'var(--card-pad)' }}><Empty>No threats in this window.</Empty></div>}
        </section>
      </div>

      <footer className="foot">
        <span>HostingInside WAF v{system?.version ?? '-'} · {system?.ruleset ?? 'rule set'} · {system?.sites ?? sites.length} sites</span>
        <Clock />
      </footer>
    </>
  )
}
