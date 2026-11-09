import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Certificate, Port, SiteView } from '../types'
import { Btn, ChipsInput, Field, IconBtn, Segmented } from '../ui'
import { AppPicker } from './AppPicker'

type Kind = 'proxy' | 'static' | 'redirect'

/** One page, in the order an engineer thinks about a new customer site:
 *  which names it answers, where the content lives, then how it is encrypted. */
export default function SiteNew() {
  const { reloadSites, notify, system } = useApp()
  const navigate = useNavigate()
  const [domains, setDomains] = useState<string[]>([])
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [kind, setKind] = useState<Kind>('proxy')
  const [origins, setOrigins] = useState<string[]>([''])
  const [lb, setLb] = useState('round_robin')
  const [adv, setAdv] = useState({ http_redirect: true, keep_host: true, hsts: false, gzip: false }) // the manager's defaults
  const [target, setTarget] = useState('')
  const [keepPath, setKeepPath] = useState(true)
  const [apps, setApps] = useState<string[]>([])
  const [tls, setTls] = useState('auto')
  const [ports, setPorts] = useState<Port[]>([{ port: system?.http_port ?? 80, https: false }, { port: system?.https_port ?? 443, https: true }])
  const [certs, setCerts] = useState<Certificate[]>([])
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  useEffect(() => { api.get<Certificate[]>('/certificates').then(setCerts).catch(() => {}) }, [])

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    const doms = domains.length ? domains : ['*']
    const encrypted = tls !== 'off'
    if (doms.includes('*') && encrypted) {
      setErr('A site that answers any host name cannot be encrypted. Add its domain, or choose "No encryption".')
      return
    }
    if (!ports.length) { setErr('Add at least one listening port.'); return }
    if (!encrypted && ports.some((p) => p.https)) { setErr('With "No encryption", every listening port must be HTTP.'); return }
    if (new Set(ports.map((p) => p.port)).size !== ports.length) { setErr('Each listening port can be used once.'); return }
    const doc: Record<string, unknown> = {
      name: name.trim() || undefined, description: description.trim() || undefined, type: kind, domains: doms, ports,
      tls: tls === 'auto' ? { mode: 'auto' } : tls === 'off' ? { mode: 'off' } : { mode: 'uploaded', cert_id: tls },
      advanced: adv,
    }
    if (kind === 'proxy') {
      doc.upstreams = origins.map((o) => o.trim()).filter(Boolean)
      if ((doc.upstreams as string[]).length > 1) doc.lb_policy = lb
    }
    if (kind === 'proxy' && apps.length) doc.waf = { apps }
    if (kind === 'redirect') doc.redirect = { url: target.trim(), code: 301, preserve_path: keepPath }
    setBusy(true)
    try {
      const s = await api.post<SiteView>('/sites', doc)
      await reloadSites()
      notify(`${s.resolved.name || s.resolved.domains[0]} is behind the WAF`)
      navigate(`/sites/${s.id}`)
    } catch (e) {
      setErr(errText(e))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={save}>
      <div className="title-row">
        <div>
          <h1>Add a site</h1>
          <p className="sub">It starts in Block with the default rule set, attack and error limits. Tune each guard on the next page.</p>
        </div>
        <div className="actions">
          <Btn onClick={() => navigate('/sites')}>Cancel</Btn>
          <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Adding' : 'Add site'}</button>
        </div>
      </div>
      {err && <p className="notice" role="alert" style={{ marginBottom: 'var(--gap)' }}>{err}</p>}
      <section className="panel" style={{ paddingTop: 0, paddingBottom: 0 }}>
        <div className="setting">
          <div><h2>Host names</h2><p className="desc">The names visitors type. The WAF answers only these; point their DNS at this server.</p></div>
          <div style={{ display: 'grid', gap: 16 }}>
            <Field label="Domains" id="domains" hint="Press Enter after each one. A leading *. covers every subdomain. Leave empty to answer any host on plain HTTP.">
              <ChipsInput id="domains" value={domains} onChange={(v) => setDomains(v.map((d) => d.toLowerCase()))} placeholder="shop.lanterntea.com.tw" />
            </Field>
            <Field label="Name in the console" id="name">
              <input id="name" className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} placeholder="Defaults to the first domain" />
            </Field>
            <Field label="Description" id="desc" hint="Optional. Who the site belongs to, or anything the team should know.">
              <textarea id="desc" className="input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} rows={2} />
            </Field>
          </div>
        </div>
        <div className="setting">
          <div><h2>Where the content lives</h2><p className="desc">Clean requests go here after every guard has let them through.</p></div>
          <div style={{ display: 'grid', gap: 16 }}>
            <div style={{ display: 'grid', gap: 10 }} role="radiogroup" aria-label="Where the content lives">
              {([
                ['proxy', 'On the customer’s server', 'Forward to one or more origins; several are load-balanced.'],
                ['static', 'In files kept on the WAF', 'Upload a .zip on the site page after adding it.'],
                ['redirect', 'Somewhere else', 'Send every visitor to another address.'],
              ] as [Kind, string, string][]).map(([v, l, h]) => (
                <label key={v} className="check" style={{ alignItems: 'flex-start' }}>
                  <input type="radio" name="kind" checked={kind === v} onChange={() => setKind(v)} style={{ marginTop: 2 }} />
                  <span><span style={{ fontWeight: 500 }}>{l}</span><span className="muted" style={{ display: 'block' }}>{h}</span></span>
                </label>
              ))}
            </div>
            {kind === 'proxy' && (
              <Field label="Origins" id="origin-0" hint="host:port, or http(s)://host:port. With more than one, requests are shared between them.">
                <div style={{ display: 'grid', gap: 8 }}>
                  {origins.map((o, i) => (
                    <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <input id={`origin-${i}`} className="input" required={i === 0} value={o} aria-label={`Origin ${i + 1}`} placeholder="10.20.1.15:8080"
                        onChange={(e) => setOrigins(origins.map((x, j) => (j === i ? e.target.value : x)))} />
                      {origins.length > 1 && <IconBtn icon="trash" label={`Remove origin ${i + 1}`} onClick={() => setOrigins(origins.filter((_, j) => j !== i))} />}
                    </div>
                  ))}
                  <Btn small icon="plus" style={{ width: 'max-content' }} onClick={() => setOrigins([...origins, ''])}>Add origin</Btn>
                </div>
              </Field>
            )}
            {kind === 'proxy' && origins.filter((o) => o.trim()).length > 1 && (
              <Field label="With several origins, pick by" id="lb">
                <select id="lb" className="input select" style={{ maxWidth: 320 }} value={lb} onChange={(e) => setLb(e.target.value)}>
                  <option value="round_robin">Turns</option><option value="ip_hash">Client IP (a visitor keeps their origin)</option><option value="least_conn">Fewest open connections</option>
                </select>
              </Field>
            )}
            {kind === 'redirect' && (
              <>
                <Field label="Send visitors to" id="target">
                  <input id="target" className="input" required type="url" value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://lanterntea.com.tw" />
                </Field>
                <label className="check"><input type="checkbox" checked={keepPath} onChange={(e) => setKeepPath(e.target.checked)} />Keep the path they asked for</label>
              </>
            )}
          </div>
        </div>
        {kind === 'proxy' && (
          <div className="setting">
            <div><h2>What runs there</h2><p className="desc">Tick the software behind this site so its own admin and editor pages aren’t mistaken for attacks. Leave all unticked for custom code.</p></div>
            <AppPicker value={apps} onChange={setApps} />
          </div>
        )}
        <div className="setting">
          <div><h2>Listening ports</h2><p className="desc">The ports visitors connect to on the WAF, each plain HTTP or HTTPS.</p></div>
          <div style={{ display: 'grid', gap: 8 }}>
            {ports.map((p, i) => (
              <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                <input className="input num" type="number" min={1} max={65535} required style={{ maxWidth: 160 }} aria-label={`Port ${i + 1}`} value={p.port}
                  onChange={(e) => setPorts(ports.map((x, j) => (j === i ? { ...x, port: Number(e.target.value) } : x)))} />
                <Segmented label={`Port ${i + 1} protocol`} value={p.https ? 'https' : 'http'}
                  onChange={(v) => setPorts(ports.map((x, j) => (j === i ? { ...x, https: v === 'https' } : x)))}
                  options={[{ value: 'http', label: 'HTTP' }, { value: 'https', label: 'HTTPS' }]} />
                {ports.length > 1 && <IconBtn icon="trash" label={`Remove port ${p.port}`} onClick={() => setPorts(ports.filter((_, j) => j !== i))} />}
              </div>
            ))}
            <Btn small icon="plus" style={{ width: 'max-content' }} onClick={() => setPorts([...ports, { port: 8080, https: false }])}>Add listening port</Btn>
          </div>
        </div>
        <div className="setting">
          <div><h2>Encryption</h2><p className="desc">The certificate for the HTTPS ports.</p></div>
          <div style={{ display: 'grid', gap: 16 }}>
            <Field label="Certificate" id="tls">
              <select id="tls" className="input select" value={tls} onChange={(e) => setTls(e.target.value)}>
                <option value="auto">Issue and renew one automatically</option>
                {certs.map((c) => <option key={c.id} value={c.id}>Uploaded: {c.name}</option>)}
                <option value="off">No encryption (plain HTTP only)</option>
              </select>
            </Field>
          </div>
        </div>
        <div className="setting">
          <div><h2>Advanced</h2><p className="desc">Usually left as they are.</p></div>
          <div style={{ display: 'grid', gap: 10 }}>
            {([['http_redirect', 'Send plain HTTP visitors to HTTPS'], ['hsts', 'Tell browsers to use HTTPS for a year (HSTS)'], ['gzip', 'Compress answers'], ['keep_host', 'Pass the visitor’s host name to the origin']] as [keyof typeof adv, string][]).map(([k, l]) => (
              <label key={k} className="check"><input type="checkbox" checked={adv[k]} onChange={(e) => setAdv({ ...adv, [k]: e.target.checked })} />{l}</label>
            ))}
          </div>
        </div>
      </section>
    </form>
  )
}
