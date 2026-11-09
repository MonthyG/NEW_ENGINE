import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useApp } from '../context'
import type { SiteCounts, SiteView } from '../types'
import { Btn, Empty, Icon, ModePill, Tabs } from '../ui'
import { int, siteName } from '../util'

type Filter = 'all' | 'block' | 'detect' | 'off'

export function guardWords(s: SiteView): string {
  const r = s.resolved
  const on: string[] = []
  if (r.access.rules?.length || r.access.block_ips?.length || r.access.allow_ips?.length || r.access.block_countries?.length ||
    r.access.allow_countries?.length || r.access.allow_groups?.length || r.access.block_groups?.length) on.push('rules')
  if (r.rate_limit.access) on.push('rate limit')
  if (r.auth.enabled) on.push('gate')
  if (r.waiting_room.enabled) on.push('queue')
  if (r.bot_challenge.enabled) on.push('bot check')
  if (r.waf.mode !== 'off') on.push('inspection')
  return on.join(' · ') || 'nothing'
}

export function originWords(s: SiteView): string {
  const r = s.resolved
  if (r.type === 'static') return 'Files kept on the WAF'
  if (r.type === 'redirect') return `Sends visitors to ${r.redirect.url}`
  return (r.upstreams ?? []).join(', ')
}

export default function Sites() {
  const { sites, sitesLoaded } = useApp()
  const navigate = useNavigate()
  const [filter, setFilter] = useState<Filter>('all')
  const [q, setQ] = useState('')
  const [counts, setCounts] = useState<SiteCounts>({})
  useEffect(() => { api.get<SiteCounts>('/site-counts').then(setCounts).catch(() => {}) }, [])

  const n = (m: Filter) => (m === 'all' ? sites.length : sites.filter((s) => s.resolved.waf.mode === m).length)
  const shown = useMemo(() => {
    const t = q.trim().toLowerCase()
    return sites
      .filter((s) => filter === 'all' || s.resolved.waf.mode === filter)
      .filter((s) => !t || siteName(s).toLowerCase().includes(t) || s.resolved.domains.some((d) => d.includes(t)) || originWords(s).includes(t) || s.resolved.project.toLowerCase().includes(t))
      .sort((a, b) => (counts[b.id]?.requests ?? 0) - (counts[a.id]?.requests ?? 0))
  }, [sites, filter, q, counts])

  return (
    <>
      <div className="title-row">
        <div>
          <h1>Sites</h1>
          <p className="sub">Every site the WAF answers for, busiest first. Counts are since midnight.</p>
        </div>
        <div className="actions">
          <Btn kind="primary" icon="plus" onClick={() => navigate('/sites/new')}>Add a site</Btn>
        </div>
      </div>
      <Tabs value={filter} onChange={setFilter} tabs={[
        { value: 'all', label: 'All', count: n('all') }, { value: 'block', label: 'Blocking', count: n('block') },
        { value: 'detect', label: 'Watching', count: n('detect') }, { value: 'off', label: 'Off', count: n('off') },
      ]} />
      <div className="toolbar">
        <label className="search">
          <Icon name="search" />
          <span className="visually-hidden">Search sites</span>
          <input className="input compact" placeholder="Domain, name, origin or project" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
        <span className="spacer" />
        <span className="stamp num">{shown.length} {shown.length === 1 ? 'site' : 'sites'}</span>
      </div>
      <section className="panel flush">
        <div className="table-wrap">
          <table className="responsive">
            <thead>
              <tr>
                <th>Site</th><th>Mode</th><th className="hide-phone">Origin</th><th className="hide-phone">Guards on</th>
                <th className="n">Requests</th><th className="n">Stopped</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((s) => (
                <tr key={s.id} className="clickable" onClick={() => navigate(`/sites/${s.id}`)}>
                  <td style={{ width: '30%' }}>
                    <a className="ident" href={`#/sites/${s.id}`} onClick={(e) => { e.preventDefault(); navigate(`/sites/${s.id}`) }}>{siteName(s)}</a>
                    <span className="sub truncate">{s.resolved.domains.map((d) => (d === '*' ? 'any host' : d)).join(', ')}{s.resolved.project ? <> · project <span className="code">{s.resolved.project}</span></> : ''}</span>
                  </td>
                  <td><ModePill mode={s.resolved.waf.mode} /></td>
                  <td className="secondary hide-phone"><span className="truncate" style={{ display: 'block', maxWidth: 260 }}>{originWords(s)}</span></td>
                  <td className="secondary hide-phone muted">{guardWords(s)}</td>
                  <td className="n num">{int(counts[s.id]?.requests ?? 0)}</td>
                  <td className="n num">{int(counts[s.id]?.blocked ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {sitesLoaded && !shown.length && (
          <div style={{ padding: 'var(--card-pad)' }}>
            <Empty>{sites.length ? 'No site matches.' : 'No sites yet. Add one to put it behind the WAF.'}</Empty>
          </div>
        )}
      </section>
    </>
  )
}
