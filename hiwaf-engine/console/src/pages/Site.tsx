import { useCallback, useEffect, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { api, errText, qs } from '../api'
import { useApp } from '../context'
import type { Attack, Certificate, Overview, Page, SiteView } from '../types'
import { Btn, ChipsInput, Confirm, Empty, Field, Segmented, Tabs } from '../ui'
import { categoryLabel, clock, int, pct, siteName, when } from '../util'
import { appLabels } from './AppPicker'
import { ChartBox } from './Overview'
import { AccessEditor, InspectionEditor, useSave } from './guards'
import { guardDefs, Stage, type GuardKey } from './Policy'
import { originWords } from './Sites'

type Tab = 'guards' | 'traffic' | 'setup'
type StageKey = 'access' | 'rate' | 'gate' | 'queue' | 'bot' | 'inspect'

const levelWord = ['', 'standard', 'strict', 'very strict', 'everything']

export default function Site() {
  const { id = '' } = useParams()
  const { siteById, sitesLoaded, notify, notifyError, reloadSites, apps } = useApp()
  const navigate = useNavigate()
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as Tab) || 'guards'
  const site = siteById[id]
  const [open, setOpen] = useState<StageKey | null>(null)
  const [ov, setOv] = useState<Overview | null>(null)
  const [recent, setRecent] = useState<Attack[]>([])
  const { save } = useSave(site ?? ({ id } as SiteView))

  const load = useCallback(() => {
    api.get<Overview>('/stats/overview' + qs({ site: id, range: '24h' })).then(setOv).catch(() => {})
    api.get<Page<Attack>>('/attacks' + qs({ site: id, size: 5 })).then((p) => setRecent(p.items)).catch(() => {})
  }, [id])
  useEffect(() => { load() }, [load])

  if (!site) return sitesLoaded ? <Empty>That site no longer exists. <Link className="card-link" to="/sites">Sites</Link></Empty> : null
  const r = site.resolved
  const act = Object.fromEntries((ov?.actions ?? []).map((a) => [a.key, a.count]))
  const flip = (k: StageKey) => setOpen(open === k ? null : k)
  const watched = recent.filter((a) => !a.blocked).length

  const setMode = async (mode: string) => {
    await save({ waf: { ...r.waf, mode } }, mode === 'block' ? 'Threats are blocked again' : mode === 'detect' ? 'Watching: threats are logged, not stopped' : 'Inspection is off')
  }

  const accessSummary = () => {
    const parts: string[] = []
    const rules = r.access.rules?.length ?? 0
    if (rules) parts.push(`${rules} rule${rules === 1 ? '' : 's'}`)
    const ips = (r.access.allow_ips?.length ?? 0) + (r.access.allow_groups?.length ?? 0)
    if (ips) parts.push(`${ips} trusted IP ${ips === 1 ? 'entry' : 'entries'}`)
    if (r.access.block_ips?.length || r.access.block_groups?.length) parts.push('refused IPs')
    if (r.access.block_countries?.length) parts.push(`refuses ${r.access.block_countries.join(', ')}`)
    if (r.access.allow_countries?.length) parts.push(`only ${r.access.allow_countries.join(', ')}`)
    return parts.join(' · ') || 'No site rules; only the rules shared by every site apply.'
  }
  return (
    <>
      <div className="title-row">
        <div>
          <h1>{siteName(site)}</h1>
          <p className="sub">{r.domains.map((d) => (d === '*' ? 'any host' : d)).join(', ')} → {originWords(site)}</p>
        </div>
        <div className="actions">
          <Segmented label="What happens to threats" value={r.waf.mode} onChange={setMode}
            options={[{ value: 'block', label: 'Block' }, { value: 'detect', label: 'Watch' }, { value: 'off', label: 'Off' }]} />
          <Btn onClick={() => navigate(`/threats?site=${site.id}`)}>Threats on this site</Btn>
        </div>
      </div>
      {r.waf.mode === 'detect' && (
        <p className="notice" style={{ marginBottom: 'var(--gap)' }}>
          Watching since {when(site.updated)}: {watched ? `${watched} recent threats were logged and let through.` : 'nothing was let through yet.'} Switch to Block once the log has no false alarms.
        </p>
      )}
      <Tabs value={tab} onChange={(t) => setParams({ tab: t })} tabs={[
        { value: 'guards', label: 'Guards' }, { value: 'traffic', label: 'Traffic' }, { value: 'setup', label: 'Setup' },
      ]} />

      {tab === 'guards' && (
        <section className="panel flush" aria-label="Guards, in the order the engine runs them">
          <Stage k="access" title="Access rules" on={!!(r.access.rules?.length || r.access.block_ips?.length || r.access.allow_ips?.length || r.access.block_countries?.length || r.access.allow_countries?.length || r.access.allow_groups?.length || r.access.block_groups?.length)}
            summary={accessSummary()} stops={act.deny ?? 0} stopsLabel="refused, 24 h" open={open === 'access'} onToggleOpen={() => flip('access')}>
            <AccessEditor site={site} onDone={() => setOpen(null)} />
          </Stage>
          {(['rate', 'gate', 'queue', 'bot'] as GuardKey[]).map((k) => {
            const g = guardDefs[k]
            return (
              <Stage key={k} k={k} title={g.title} on={g.on(r)} summary={g.summary(r)} stops={g.showStops(r) ? act[g.act] ?? 0 : undefined} stopsLabel={g.stopsLabel}
                open={open === k} onToggleOpen={() => flip(k)} toggle={g.toggle?.(r, save, () => setOpen(k))}>
                <g.Editor site={site} onDone={() => setOpen(null)} />
              </Stage>
            )
          })}
          <Stage k="inspect" title="Threat inspection" on={r.waf.mode !== 'off'}
            summary={r.waf.mode === 'off' ? 'Off: requests are not inspected.' : <>{r.waf.mode === 'block' ? 'Stops' : 'Logs but lets through'} threats at the <strong>{levelWord[r.waf.paranoia]}</strong> level; {Object.values(r.waf.protections).filter(Boolean).length} of {Object.keys(r.waf.protections).length} kinds checked{r.waf.apps?.length ? <>; <strong>{appLabels(r.waf.apps, apps)}</strong> admin allowed</> : ''}{r.exclusions?.length ? `; ${r.exclusions.length} rule exception${r.exclusions.length > 1 ? 's' : ''}` : ''}</>}
            stops={act.block ?? 0} stopsLabel={r.waf.mode === 'detect' ? 'stopped (Watch)' : 'stopped, 24 h'} open={open === 'inspect'} onToggleOpen={() => flip('inspect')}>
            <InspectionEditor site={site} onDone={() => setOpen(null)} />
          </Stage>
          <div className="stage">
            <div className="rail-line"><span className="node" style={{ borderColor: 'var(--text)' }} /></div>
            <div>
              <h3>Origin</h3>
              <div className="summary">{originWords(site)}{r.type === 'proxy' && (r.upstreams?.length ?? 0) > 1 ? ` · balanced by ${r.lb_policy === 'ip_hash' ? 'client IP' : r.lb_policy === 'least_conn' ? 'fewest connections' : 'turns'}` : ''}</div>
            </div>
            <div className="side"><div className="stops"><div className="figure num">{int(act[''] !== undefined ? (act[''] ?? 0) + (act.allow ?? 0) : 0)}</div><div className="label">reached it, 24 h</div></div></div>
          </div>
        </section>
      )}

      {tab === 'traffic' && <Traffic site={site} ov={ov} recent={recent} />}
      {tab === 'setup' && <Setup site={site} onDeleted={async () => { await reloadSites(); notify('Site removed'); navigate('/sites') }} onError={notifyError} />}
    </>
  )
}

function Traffic({ site, ov, recent }: { site: SiteView; ov: Overview | null; recent: Attack[] }) {
  const req = ov?.requests ?? 0
  return (
    <div className="sheet">
      <div className="kpis span-12">
        <div className="kpi"><div className="kpi-label">Requests, 24 h</div><div className="kpi-value num">{int(req)}</div></div>
        <div className="kpi"><div className="kpi-label">Refused or stopped</div><div className="kpi-value num">{int(ov?.blocked ?? 0)}<small>{pct(ov?.blocked ?? 0, req)}</small></div></div>
        <div className="kpi"><div className="kpi-label">Client IPs</div><div className="kpi-value num">{int(ov?.unique_ips ?? 0)}</div></div>
        <div className="kpi"><div className="kpi-label">4xx answers</div><div className="kpi-value num">{int(ov?.err_4xx ?? 0)}</div></div>
        <div className="kpi"><div className="kpi-label">5xx answers</div><div className={'kpi-value num' + ((ov?.err_5xx ?? 0) > 0 ? ' neg-text' : '')}>{int(ov?.err_5xx ?? 0)}</div></div>
      </div>
      <section className="panel span-7">
        <header><h2>Requests, 24 h</h2><span className="meta">stopped in blue</span></header>
        <ChartBox label="Requests and stopped requests" deps={[ov]} height={200} draw={(el) => {
          if (!ov) return
          window.Charts.line(el, { labels: ov.series.map((p) => clock(p.t)), height: 200, series: [
            { name: 'Requests', values: ov.series.map((p) => p.requests) },
            { name: 'Stopped', values: ov.series.map((p) => p.blocked) },
          ] })
        }} />
      </section>
      <section className="panel span-5 flush">
        <header><h2>Latest threats</h2><Link className="card-link" to={`/threats?site=${site.id}`}>All</Link></header>
        <div className="rows" style={{ padding: '4px var(--card-pad) 8px' }}>
          {recent.length ? recent.map((a) => (
            <div key={a.tx_id} className="row">
              <div className="grow"><div className="truncate">{categoryLabel(a.categories[0] ?? '')} from <span className="num">{a.client_ip}</span></div><div className="muted truncate">{a.method} {a.uri}</div></div>
              <div style={{ textAlign: 'right' }}><div className={a.blocked ? '' : 'warn-text'}>{a.blocked ? 'Stopped' : 'Watched'}</div><div className="muted num">{when(a.ts)}</div></div>
            </div>
          )) : <Empty>No threats on this site.</Empty>}
        </div>
      </section>
    </div>
  )
}

function Setup({ site, onDeleted, onError }: { site: SiteView; onDeleted: () => void; onError: (e: unknown) => void }) {
  const r = site.resolved
  const { busy, err, save } = useSave(site)
  const [domains, setDomains] = useState(r.domains.filter((d) => d !== '*'))
  const [name, setName] = useState(r.name)
  const [origins, setOrigins] = useState((r.upstreams ?? []).join(', '))
  const [lb, setLb] = useState(r.lb_policy || 'round_robin')
  const [target, setTarget] = useState(r.redirect.url)
  const [cert, setCert] = useState(r.tls.mode === 'uploaded' ? r.tls.cert_id || 'legacy' : r.tls.mode)
  const [adv, setAdv] = useState(r.advanced)
  const [title, setTitle] = useState(r.block_page.title)
  const [message, setMessage] = useState(r.block_page.message)
  const [certs, setCerts] = useState<Certificate[]>([])
  const [del, setDel] = useState(false)
  const [upload, setUpload] = useState('')
  useEffect(() => { api.get<Certificate[]>('/certificates').then(setCerts).catch(() => {}) }, [])

  const http = r.ports.find((p) => !p.https)?.port ?? 80
  const https = r.ports.find((p) => p.https)?.port ?? 443
  const saveAll = () => {
    const doms = domains.length ? domains : ['*']
    const patch: Record<string, unknown> = {
      name, domains: doms, advanced: adv, block_page: { title, message },
      tls: cert === 'off' ? { mode: 'off' } : cert === 'auto' ? { mode: 'auto' } : cert === 'legacy' ? { mode: 'uploaded' } : { mode: 'uploaded', cert_id: cert },
      ports: cert === 'off' ? [{ port: http, https: false }] : [{ port: http, https: false }, { port: https, https: true }],
    }
    if (r.type === 'proxy') { patch.upstreams = origins.split(/[\s,]+/).filter(Boolean); patch.lb_policy = lb }
    if (r.type === 'redirect') patch.redirect = { ...r.redirect, url: target }
    save(patch, 'Setup saved')
  }
  const sendZip = async (f: File) => {
    const fd = new FormData()
    fd.append('file', f)
    try {
      const res = await api.upload<{ files: number }>(`/sites/${site.id}/static`, fd)
      setUpload(`${res.files} files are live.`)
    } catch (e) {
      setUpload(errText(e))
    }
  }

  return (
    <section className="panel" style={{ paddingTop: 0, paddingBottom: 0 }}>
      <div className="setting">
        <div><h2>Host names</h2><p className="desc">The names this site answers. Changing them changes which certificates are issued.</p></div>
        <div style={{ display: 'grid', gap: 16 }}>
          <Field label="Domains" id="sd"><ChipsInput id="sd" value={domains} onChange={(v) => setDomains(v.map((d) => d.toLowerCase()))} /></Field>
          <Field label="Name in the console" id="sn"><input id="sn" className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} /></Field>
        </div>
      </div>
      <div className="setting">
        <div><h2>Content</h2><p className="desc">{r.type === 'proxy' ? 'Clean requests are forwarded to these origins.' : r.type === 'static' ? 'Files kept on the WAF itself.' : 'Every visitor is sent elsewhere.'}</p></div>
        <div style={{ display: 'grid', gap: 16 }}>
          {r.type === 'proxy' && (
            <>
              <Field label="Origins" id="so" hint="Separate several with a comma."><input id="so" className="input" value={origins} onChange={(e) => setOrigins(e.target.value)} /></Field>
              <Field label="With several origins, pick by" id="slb">
                <select id="slb" className="input select" style={{ maxWidth: 320 }} value={lb} onChange={(e) => setLb(e.target.value)}>
                  <option value="round_robin">Turns</option><option value="ip_hash">Client IP (a visitor keeps their origin)</option><option value="least_conn">Fewest open connections</option>
                </select>
              </Field>
            </>
          )}
          {r.type === 'redirect' && <Field label="Send visitors to" id="st"><input id="st" className="input" value={target} onChange={(e) => setTarget(e.target.value)} /></Field>}
          {r.type === 'static' && (
            <Field label="Site files" id="sz" hint={upload || 'A .zip with index.html at its top level, or in one folder. It replaces the current files.'}>
              <label className="btn" style={{ width: 'max-content' }}>Upload a .zip<input id="sz" hidden type="file" accept=".zip,application/zip" onChange={(e) => e.target.files?.[0] && sendZip(e.target.files[0])} /></label>
            </Field>
          )}
        </div>
      </div>
      <div className="setting">
        <div><h2>Encryption</h2><p className="desc">HTTPS on {https}; HTTP on {http}.</p></div>
        <div style={{ display: 'grid', gap: 12 }}>
          <Field label="Certificate" id="sc">
            <select id="sc" className="input select" value={cert} onChange={(e) => setCert(e.target.value)}>
              <option value="auto">Issued and renewed automatically</option>
              {cert === 'legacy' && <option value="legacy">Uploaded for this site</option>}
              {certs.map((c) => <option key={c.id} value={c.id}>Uploaded: {c.name}</option>)}
              <option value="off">No encryption</option>
            </select>
          </Field>
          {[['http_redirect', 'Send plain HTTP visitors to HTTPS'], ['hsts', 'Tell browsers to use HTTPS for a year (HSTS)'], ['gzip', 'Compress answers'], ['keep_host', 'Pass the visitor’s host name to the origin']].map(([k, l]) => (
            <label key={k} className="check"><input type="checkbox" checked={(adv as any)[k]} onChange={(e) => setAdv({ ...adv, [k]: e.target.checked })} />{l}</label>
          ))}
        </div>
      </div>
      <div className="setting">
        <div><h2>Refusal page</h2><p className="desc">What a refused visitor reads. The engine adds the event number to it.</p></div>
        <div style={{ display: 'grid', gap: 16 }}>
          <Field label="Heading" id="bt"><input id="bt" className="input" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} /></Field>
          <Field label="Message" id="bm"><textarea id="bm" className="input" maxLength={2000} value={message} onChange={(e) => setMessage(e.target.value)} /></Field>
        </div>
      </div>
      <div className="setting">
        <div />
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <Btn kind="primary" disabled={busy} onClick={saveAll}>{busy ? 'Saving' : 'Save setup'}</Btn>
          {err && <span className="error-line" role="alert">{err}</span>}
        </div>
      </div>
      <div className="setting">
        <div><h2>Remove this site</h2><p className="desc">The WAF stops answering for {r.domains[0]}. Its logs stay until they age out.</p></div>
        <div><Btn kind="danger" onClick={() => setDel(true)}>Remove {siteName(site)}</Btn></div>
      </div>
      <Confirm open={del} danger title={`Remove ${siteName(site)}?`} confirm="Remove site" onClose={() => setDel(false)}
        onConfirm={async () => { setDel(false); try { await api.del(`/sites/${site.id}`); onDeleted() } catch (e) { onError(e) } }}>
        Visitors to {r.domains.join(', ')} will get "unknown site" until it is added again.
      </Confirm>
    </section>
  )
}
