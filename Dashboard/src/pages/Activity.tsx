import { useCallback, useEffect, useState } from 'react'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { EventRow, Page } from '../types'
import { Empty, Icon, Pager, Pill, Tabs, useInterval } from '../ui'
import { countryName, eventLabels, siteName, when } from '../util'

const kinds = {
  all: { label: 'Everything', types: ['ip_block', 'geo_block', 'rule_block', 'allowed_by_rule', 'rate_limit_ban', 'challenge_passed', 'challenge_failed', 'auth_passed', 'auth_failed'] },
  refused: { label: 'Refused', types: ['ip_block', 'geo_block', 'rule_block'] },
  let: { label: 'Let in by rule', types: ['allowed_by_rule'] },
  bans: { label: 'Bans', types: ['rate_limit_ban'] },
  bot: { label: 'Bot check', types: ['challenge_passed', 'challenge_failed'] },
  gate: { label: 'Password gate', types: ['auth_passed', 'auth_failed'] },
}
type Kind = keyof typeof kinds
const good = new Set(['allowed_by_rule', 'challenge_passed', 'auth_passed'])

export default function Activity() {
  const { sites, siteById, notifyError } = useApp()
  const [kind, setKind] = useState<Kind>('all')
  const [site, setSite] = useState('')
  const [ip, setIp] = useState('')
  const [pg, setPg] = useState(0)
  const [rows, setRows] = useState<Page<EventRow>>({ items: [], total: 0 })
  const load = useCallback(() => {
    api.get<Page<EventRow>>('/logs' + qs({ types: kinds[kind].types.join(','), site, ip: ip.trim(), page: pg + 1, size: 25 })).then(setRows).catch(notifyError)
  }, [kind, site, ip, pg, notifyError])
  useEffect(() => { load() }, [load])
  useInterval(load, 30_000)

  return (
    <>
      <div className="title-row">
        <div>
          <h1>Activity</h1>
          <p className="sub">What the access rules, rate limits, bot check and password gate did, newest first. Threats have their own page.</p>
        </div>
      </div>
      <Tabs value={kind} onChange={(k) => { setKind(k); setPg(0) }} tabs={(Object.keys(kinds) as Kind[]).map((k) => ({ value: k, label: kinds[k].label }))} />
      <div className="toolbar">
        <label className="search">
          <Icon name="search" />
          <span className="visually-hidden">Source IP</span>
          <input className="input compact" placeholder="Source IP" value={ip} onChange={(e) => { setIp(e.target.value); setPg(0) }} />
        </label>
        <select aria-label="Site" className="select compact" value={site} onChange={(e) => { setSite(e.target.value); setPg(0) }}>
          <option value="">Every site</option>
          {sites.map((s) => <option key={s.id} value={s.id}>{siteName(s)}</option>)}
        </select>
        <span className="spacer" />
        <span className="stamp num">{rows.total} events</span>
      </div>
      <section className="panel flush">
        <div className="table-wrap">
          <table className="responsive">
            <thead><tr><th>When</th><th>What happened</th><th>Source</th><th className="hide-phone">Request</th><th className="hide-phone">Because of</th></tr></thead>
            <tbody>
              {rows.items.map((e) => (
                <tr key={e.id}>
                  <td className="num" style={{ whiteSpace: 'nowrap' }}>{when(e.ts)}</td>
                  <td><Pill tone={good.has(e.type) ? 'pos' : e.type === 'challenge_failed' || e.type === 'auth_failed' ? 'warn' : 'neg'}>{eventLabels[e.type] ?? e.type}</Pill></td>
                  <td><span className="num">{e.client_ip}</span><span className="sub">{countryName(e.country)}</span></td>
                  <td className="secondary hide-phone" style={{ maxWidth: 360 }}>
                    <span className="truncate" style={{ display: 'block' }}>{siteName(siteById[e.site_id], e.site_id)}</span>
                    <span className="sub code truncate">{e.method} {e.uri}</span>
                  </td>
                  <td className="secondary hide-phone muted">{e.detail || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!rows.items.length && <div style={{ padding: 'var(--card-pad)' }}><Empty>Nothing like that has happened yet.</Empty></div>}
        <div style={{ padding: '0 var(--card-pad)' }}><Pager total={rows.total} page={pg} size={25} onPage={setPg} /></div>
      </section>
    </>
  )
}
