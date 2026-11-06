import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { Attack, AttackDetail, GroupRow, Page } from '../types'
import { Btn, Empty, Pager, Pill, Segmented, useInterval } from '../ui'
import { categoryLabel, categoryLabels, clock, countryName, span, siteName, when } from '../util'
import { appHint } from './AppPicker'
import ExclusionDialog, { fieldFrom, pathFrom } from './ExclusionDialog'

type Range = '24h' | '7d' | '30d'

export default function Threats() {
  const { sites, siteById, notify, notifyError, apps, reloadSites } = useApp()
  const [params, setParams] = useSearchParams()
  const site = params.get('site') ?? ''
  const category = params.get('category') ?? ''
  const [range, setRange] = useState<Range>('24h')
  const [sources, setSources] = useState<Page<GroupRow>>({ items: [], total: 0 })
  const [srcPage, setSrcPage] = useState(0)
  // the selected source is ip + src (its site); site alone is the list's filter
  const sel = { ip: params.get('ip') ?? '', site: params.get('src') ?? params.get('site') ?? '' }
  const [rows, setRows] = useState<Page<Attack>>({ items: [], total: 0 })
  const [rowPage, setRowPage] = useState(0)
  const [openTx, setOpenTx] = useState<string | null>(null)
  const [detail, setDetail] = useState<AttackDetail | null>(null)
  const [falseAlarm, setFalseAlarm] = useState<{ site: string; rule: number; msg: string; field: string; path: string } | null>(null)

  const set = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) v ? next.set(k, v) : next.delete(k)
    setParams(next, { replace: true })
  }

  const loadSources = useCallback(() => {
    api.get<Page<GroupRow>>('/attacks/groups' + qs({ site, category, range, size: 12, page: srcPage + 1 })).then((p) => {
      setSources(p)
      if (!params.get('ip') && p.items[0]) {
        const next = new URLSearchParams(params)
        next.set('ip', p.items[0].client_ip)
        next.set('src', p.items[0].site_id)
        setParams(next, { replace: true })
      }
    }).catch(notifyError)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [site, category, range, srcPage, notifyError])
  useEffect(() => { loadSources() }, [loadSources])
  useInterval(loadSources, 30_000)

  useEffect(() => {
    setRowPage(0)
    setOpenTx(null)
  }, [sel.ip, sel.site])
  useEffect(() => {
    if (!sel.ip) { setRows({ items: [], total: 0 }); return }
    api.get<Page<Attack>>('/attacks' + qs({ ip: sel.ip, site: sel.site, category, range, size: 10, page: rowPage + 1 })).then(setRows).catch(notifyError)
  }, [sel.ip, sel.site, category, range, rowPage, notifyError])
  useEffect(() => {
    setDetail(null)
    if (openTx) api.get<AttackDetail>(`/attacks/${encodeURIComponent(openTx)}`).then(setDetail).catch(notifyError)
  }, [openTx, notifyError])

  const current = sources.items.find((g) => g.client_ip === sel.ip && (!sel.site || g.site_id === sel.site))
  const stopped = rows.items.filter((a) => a.blocked).length

  const enableApp = async (siteId: string, key: string, label: string) => {
    const s = siteById[siteId]
    try {
      await api.patch(`/sites/${siteId}`, { waf: { ...s.resolved.waf, apps: [...(s.resolved.waf.apps ?? []), key] } })
      await reloadSites()
      notify(`${label} profile is on for ${siteName(s)}`)
    } catch (e) {
      notifyError(e)
    }
  }

  const refuse = async (everywhere: boolean) => {
    if (!sel.ip) return
    try {
      await api.post('/rules', {
        name: `Refuse ${sel.ip}${everywhere ? '' : ` on ${siteName(siteById[sel.site], sel.site)}`}`, enabled: true, action: 'block',
        sites: everywhere ? [] : [sel.site], match: { ip: [sel.ip] }, priority: 0,
      })
      notify(everywhere ? `${sel.ip} is refused on every site` : `${sel.ip} is refused on ${siteName(siteById[sel.site], sel.site)}`)
    } catch (e) {
      notifyError(e)
    }
  }

  return (
    <>
      <div className="title-row">
        <div>
          <h1>Threats</h1>
          <p className="sub">Requests the rule set flagged, grouped by where they came from. Newest source first.</p>
        </div>
        <div className="actions">
          <select aria-label="Site" className="select compact" value={site} onChange={(e) => { set({ site: e.target.value, ip: '', src: '' }); setSrcPage(0) }}>
            <option value="">Every site</option>
            {sites.map((s) => <option key={s.id} value={s.id}>{siteName(s)}</option>)}
          </select>
          <select aria-label="Kind of threat" className="select compact" value={category} onChange={(e) => { set({ category: e.target.value, ip: '', src: '' }); setSrcPage(0) }}>
            <option value="">Every kind</option>
            {Object.entries(categoryLabels).filter(([k]) => k).map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
          <Segmented label="Time window" value={range} onChange={(r) => { setRange(r); setSrcPage(0) }}
            options={[{ value: '24h', label: '24 hours' }, { value: '7d', label: '7 days' }, { value: '30d', label: '30 days' }]} />
        </div>
      </div>

      <div className="inbox">
        <section className="panel flush" aria-label="Sources">
          <header><h2>Sources</h2><span className="meta num">{sources.total}</span></header>
          <div role="listbox" aria-label="Threat sources" style={{ marginTop: 6 }}>
            {sources.items.map((g) => (
              <button key={g.site_id + g.client_ip} type="button" className="source" role="option"
                aria-selected={g.client_ip === sel.ip && g.site_id === sel.site}
                onClick={() => set({ ip: g.client_ip, src: g.site_id })}>
                <span className="ip num">{g.client_ip}</span>
                <span className="count num">{g.count}</span>
                <span className="meta truncate">{countryName(g.country)} · {siteName(siteById[g.site_id], g.site_id)}</span>
                <span className="meta">{when(g.last)}</span>
              </button>
            ))}
            {!sources.items.length && <div style={{ padding: '0 var(--card-pad) var(--card-pad)' }}><Empty>No threats in this window.</Empty></div>}
          </div>
          <div style={{ padding: '0 var(--card-pad)' }}><Pager total={sources.total} page={srcPage} size={12} onPage={setSrcPage} /></div>
        </section>

        <section className="panel" aria-label="Selected source">
          {current || sel.ip ? (
            <>
              <div className="panel-head" style={{ alignItems: 'flex-start', flexWrap: 'wrap' }}>
                <div>
                  <h2 className="num" style={{ fontSize: 20, lineHeight: '28px' }}>{sel.ip}</h2>
                  <p className="muted">
                    {current ? <>{countryName(current.country)} · {current.count} threats against {siteName(siteById[current.site_id], current.site_id)} over {span(current.first, current.last)}, last {when(current.last)}</> : 'Loading'}
                  </p>
                </div>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  <Btn onClick={() => refuse(false)}>Refuse on this site</Btn>
                  <Btn kind="primary" onClick={() => refuse(true)}>Refuse everywhere</Btn>
                </div>
              </div>
              <p className="meta" style={{ marginBottom: 8 }}>{stopped} of {rows.items.length} shown were stopped{rows.items.length > stopped ? '; the rest were let through because the site is in Watch' : ''}.</p>
              <div className="rows">
                {rows.items.map((a) => (
                  <div key={a.tx_id}>
                    <button type="button" className="row" aria-expanded={openTx === a.tx_id} onClick={() => setOpenTx(openTx === a.tx_id ? null : a.tx_id)}
                      style={{ width: '100%', border: 0, borderTop: '1px solid var(--rule)', background: 'none', textAlign: 'left', cursor: 'pointer' }}>
                      <span className="num muted" style={{ width: 48 }}>{clock(a.ts)}</span>
                      <span className="grow">
                        <span style={{ display: 'block', fontWeight: 500 }}>{a.categories.map(categoryLabel).join(', ')}</span>
                        <span className="code muted truncate" style={{ display: 'block' }}>{a.method || 'GET'} {a.uri}</span>
                      </span>
                      {a.blocked ? <Pill tone="neg">Stopped</Pill> : <Pill tone="warn">Let through</Pill>}
                    </button>
                    {openTx === a.tx_id && (
                      <div style={{ padding: '4px 0 16px 60px' }}>
                        {!detail ? <span className="muted">Loading</span> : (
                          <>
                            <dl className="kv">
                              <dt>Site</dt><dd>{siteName(siteById[a.site_id], a.site_id)} ({a.host})</dd>
                              <dt>Answer</dt><dd className="num">{detail.request?.status ?? a.status}{detail.request ? ` in ${detail.request.duration_ms.toFixed(1)} ms` : ''}</dd>
                              <dt>Browser</dt><dd className="truncate">{detail.request?.user_agent || '—'}</dd>
                              <dt>Event</dt><dd className="code">{a.tx_id}</dd>
                            </dl>
                            {(() => {
                              const hint = appHint(siteById[a.site_id], a.uri, apps)
                              const s = siteById[a.site_id]
                              return hint && s && (
                                <div className="notice" style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', margin: '8px 0' }}>
                                  <span className="grow">This looks like {hint.label}’s own admin. If this site runs {hint.label}, its profile stops these false alarms on every admin page at once.</span>
                                  <Btn small kind="primary" onClick={() => enableApp(s.id, hint.key, hint.label)}>Turn on {hint.label}</Btn>
                                </div>
                              )
                            })()}
                            <div className="match-list">
                              {detail.matches.filter((m) => m.category !== 'score').map((m) => (
                                <div key={m.id}>
                                  <div style={{ display: 'flex', gap: 8, alignItems: 'baseline', flexWrap: 'wrap' }}>
                                    <span className="grow"><span className="num muted">Rule {m.rule_id}</span> · {m.detail}</span>
                                    {m.category && (
                                      <Btn small onClick={() => setFalseAlarm({ site: a.site_id, rule: Number(m.rule_id), msg: m.detail, field: fieldFrom(m.data), path: pathFrom(a.uri) })}>False alarm</Btn>
                                    )}
                                  </div>
                                  {m.data && <div className="payload code">{m.data}</div>}
                                </div>
                              ))}
                            </div>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
              <Pager total={rows.total} page={rowPage} size={10} onPage={setRowPage} />
            </>
          ) : <Empty>Choose a source to see what it sent.</Empty>}
        </section>
      </div>
      <ExclusionDialog open={!!falseAlarm} siteId={falseAlarm?.site ?? ''} rule={falseAlarm?.rule ?? 0} msg={falseAlarm?.msg}
        field={falseAlarm?.field ?? ''} path={falseAlarm?.path ?? '/'} onClose={() => setFalseAlarm(null)} />
    </>
  )
}
