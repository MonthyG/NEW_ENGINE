import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { SiteView } from '../types'
import { Btn, Field, Mark, ThemeToggle } from '../ui'

// The public address customers point their DNS at: WAF_IP in the container's environment
// (served as /env.js), else VITE_WAF_IP for `npm run dev` (see .env.example).
const runtime = (window as { __ENV?: { WAF_IP?: string } }).__ENV
export const WAF_IP: string = runtime?.WAF_IP || import.meta.env.VITE_WAF_IP || window.location.hostname

type Step = 'ask' | 'skipped' | 'setup' | 'dns'

/** A customer's first visit, and every "Protect a website" after it:
 *  ask whether they want the WAF, take one domain and its server, then show the DNS change.
 *  Each step maps to one portal page: /console/waf (ask), /console/waf/setup, /console/waf/dns. */
export default function Welcome({ start = 'ask', inShell = false }: { start?: Step; inShell?: boolean }) {
  const [step, setStep] = useState<Step>(start)
  const [site, setSite] = useState<SiteView | null>(null)
  const Wrap = inShell ? 'div' : 'main' // the shell already has the page's <main>
  return (
    <Wrap className={inShell ? undefined : 'canvas'} style={{ maxWidth: 820 }}>
      {!inShell && <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 32 }}>
        <Mark size={24} /><span className="product" style={{ fontWeight: 600 }}>WAF</span>
        <span className="spacer" style={{ flex: 1 }} /><ThemeToggle />
      </div>}
      {step === 'ask' && <Ask onYes={() => setStep('setup')} onNo={() => setStep('skipped')} />}
      {step === 'skipped' && <Skipped onYes={() => setStep('setup')} />}
      {step === 'setup' && <Setup onDone={(s) => { setSite(s); setStep('dns') }} />}
      {step === 'dns' && site && <Dns site={site} />}
    </Wrap>
  )
}

function Ask({ onYes, onNo }: { onYes: () => void; onNo: () => void }) {
  return (
    <section>
      <div className="title-row">
        <div>
          <h1>Protect your website with the WAF?</h1>
          <p className="sub">Visitors reach your site through our firewall first. Attacks are stopped there; normal visitors pass straight through to your server.</p>
        </div>
      </div>
      <section className="panel" style={{ display: 'grid', gap: 12 }}>
        <ul style={{ display: 'grid', gap: 8, paddingLeft: 18 }}>
          <li>Blocks SQL injection, cross-site scripting and other common attacks (OWASP rule set).</li>
          <li>Limits floods and bad bots, so your server stays up.</li>
          <li>Free HTTPS certificate, issued and renewed for you.</li>
          <li>Setup takes about two minutes: your domain, your server's IP, then one DNS change.</li>
        </ul>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 8 }}>
          <Btn kind="primary" icon="plus" onClick={onYes}>Yes, protect a website</Btn>
          {/* In the portal "Not now" goes back to the portal's home page. */}
          <Btn onClick={onNo}>Not now</Btn>
        </div>
      </section>
    </section>
  )
}

function Skipped({ onYes }: { onYes: () => void }) {
  return (
    <section className="panel" style={{ display: 'grid', gap: 12 }}>
      <h1 style={{ fontSize: 'var(--fs-card)', fontWeight: 600 }}>No problem</h1>
      <p className="muted">Nothing was set up and nothing runs for you. You can turn the WAF on here any time.</p>
      <div><Btn kind="primary" icon="plus" onClick={onYes}>Protect a website</Btn></div>
    </section>
  )
}

/** "https://www.Shop.com/path" -> "www.shop.com" */
export function cleanDomain(v: string): string {
  return v.trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '').replace(/\.$/, '')
}

function Setup({ onDone }: { onDone: (s: SiteView) => void }) {
  const { reloadSites, notify } = useApp()
  const [domain, setDomain] = useState('')
  const [www, setWww] = useState(true)
  const [ip, setIp] = useState('')
  const [https, setHttps] = useState(false)
  const [port, setPort] = useState('80')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const d = cleanDomain(domain)
  const bare = d.replace(/^www\./, '')
  const domains = www && !d.startsWith('*.') ? [bare, `www.${bare}`] : [d]

  const save = async (e: React.FormEvent) => {
    e.preventDefault()
    setErr('')
    if (!/^(\*\.)?([a-z0-9-]+\.)+[a-z]{2,}$/.test(d)) { setErr('Enter a domain like shop.example.com.'); return }
    setBusy(true)
    try {
      // The manager checks the rest: an IP (not a host name), not loopback, a domain no one else uses.
      const s = await api.post<SiteView>('/sites', {
        type: 'proxy', domains,
        upstreams: [`${https ? 'https' : 'http'}://${ip.trim()}:${port}`],
      })
      await reloadSites()
      notify(`${domains[0]} is behind the WAF`)
      onDone(s)
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
          <h1>Your website</h1>
          <p className="sub">It starts in Block with the recommended protection. You can change everything later.</p>
        </div>
      </div>
      {err && <p className="notice" role="alert" style={{ marginBottom: 'var(--gap)' }}>{err}</p>}
      <section className="panel" style={{ display: 'grid', gap: 16 }}>
        <Field label="Domain" id="w-domain" hint="The address visitors type.">
          <input id="w-domain" className="input" required autoFocus value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="shop.example.com" autoComplete="off" spellCheck={false} />
        </Field>
        {!d.startsWith('*.') && (
          <label className="check"><input type="checkbox" checked={www} onChange={(e) => setWww(e.target.checked)} />Also protect www.{bare || 'your domain'}</label>
        )}
        <Field label="Your server's IP address" id="w-ip" hint="Where the website really runs. Visitors will no longer reach it directly.">
          <input id="w-ip" className="input" required value={ip} onChange={(e) => setIp(e.target.value)} placeholder="203.0.113.10" inputMode="decimal" autoComplete="off" spellCheck={false} />
        </Field>
        <label className="check">
          <input type="checkbox" checked={https} onChange={(e) => { setHttps(e.target.checked); setPort(e.target.checked ? '443' : '80') }} />
          My server already uses HTTPS
        </label>
        <Field label="Port on your server" id="w-port" hint="Usually 80, or 443 with HTTPS.">
          <input id="w-port" className="input num" type="number" min={1} max={65535} required style={{ maxWidth: 160 }} value={port} onChange={(e) => setPort(e.target.value)} />
        </Field>
        <div><button type="submit" className="btn primary" disabled={busy}>{busy ? 'Adding' : 'Continue'}</button></div>
      </section>
    </form>
  )
}

type Check = Record<string, 'ok' | 'wrong' | 'none' | 'error'>

// shortcut: checks DNS from the browser over Cloudflare DNS-over-HTTPS; the portal should do this server-side.
async function resolves(name: string): Promise<'ok' | 'wrong' | 'none' | 'error'> {
  try {
    const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=A`, { headers: { Accept: 'application/dns-json' } })
    const j = await r.json()
    const ips: string[] = (j.Answer ?? []).filter((a: any) => a.type === 1).map((a: any) => a.data)
    return ips.includes(WAF_IP) ? 'ok' : ips.length ? 'wrong' : 'none'
  } catch {
    return 'error'
  }
}

const checkWord = { ok: 'Pointing at the WAF', wrong: 'Still points somewhere else', none: 'No record yet', error: 'Could not check' }

function Dns({ site }: { site: SiteView }) {
  const navigate = useNavigate()
  const names = site.resolved.domains
  const [check, setCheck] = useState<Check>({})
  const [busy, setBusy] = useState(false)
  const run = async () => {
    setBusy(true)
    setCheck(Object.fromEntries(await Promise.all(names.map(async (n) => [n, await resolves(n)]))))
    setBusy(false)
  }
  const allOk = names.length > 0 && names.every((n) => check[n] === 'ok')
  return (
    <section>
      <div className="title-row">
        <div>
          <h1>Point your domain at the WAF</h1>
          <p className="sub">At your domain registrar or DNS provider, set these records. Remove any other A or AAAA records for the same names. Changes usually show within minutes, sometimes a few hours.</p>
        </div>
      </div>
      <section className="panel flush">
        <div className="table-wrap">
          <table className="responsive">
            <thead><tr><th>Type</th><th>Name</th><th>Value</th><th>Status</th></tr></thead>
            <tbody>
              {names.map((n) => (
                <tr key={n}>
                  <td className="num">A</td>
                  <td className="num">{n}</td>
                  <td className="num">{WAF_IP}</td>
                  <td className={check[n] === 'ok' ? 'pos-text' : check[n] ? 'neg-text' : 'muted'}>{check[n] ? checkWord[check[n]] : 'Not checked'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 'var(--gap)' }}>
        <Btn icon="refresh" onClick={run} disabled={busy}>{busy ? 'Checking' : 'Check DNS'}</Btn>
        <Btn kind={allOk ? 'primary' : undefined} onClick={() => navigate('/overview')}>{allOk ? 'Go to the dashboard' : 'I’ll do it later, go to the dashboard'}</Btn>
      </div>
      <p className="muted" style={{ marginTop: 12 }}>Your site is saved. Next time you sign in you go straight to the dashboard.</p>
    </section>
  )
}
