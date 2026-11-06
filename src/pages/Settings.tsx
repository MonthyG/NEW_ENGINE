import { useCallback, useEffect, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import QRCode from 'qrcode'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Alerts, Backup, Certificate, Me, Rulesets, Token } from '../types'
import { Btn, Confirm, Dialog, Empty, Field, IconBtn, Pill, Tabs } from '../ui'
import { daysLeft, dateTime, siteName, when } from '../util'
import { DEMO } from '../api'

const areas = [
  { value: 'certificates', label: 'Certificates' }, { value: 'account', label: 'Your account' },
  { value: 'tokens', label: 'API tokens' }, { value: 'system', label: 'System' },
] as const
type Area = (typeof areas)[number]['value']

export default function Settings() {
  const { area = 'certificates' } = useParams()
  const navigate = useNavigate()
  const a = (areas.find((x) => x.value === area)?.value ?? 'certificates') as Area
  return (
    <>
      <div className="title-row">
        <div>
          <h1>{areas.find((x) => x.value === a)!.label}</h1>
          <p className="sub">{{
            certificates: 'Certificates you uploaded, soonest to expire first. Sites on automatic certificates need nothing here.',
            account: 'Your password and two-step sign-in for this console.',
            tokens: 'Keys that let scripts and the cloud control plane call the API.',
            system: 'The engine behind this console: its rule set, database backups and who hears when it goes down.',
          }[a]}</p>
        </div>
      </div>
      <Tabs value={a} onChange={(v) => navigate(`/settings/${v}`)} tabs={areas.map((x) => ({ value: x.value, label: x.label }))} />
      {a === 'certificates' && <Certs />}
      {a === 'account' && <Account />}
      {a === 'tokens' && <Tokens />}
      {a === 'system' && <System />}
    </>
  )
}

function Certs() {
  const { siteById, notify, notifyError } = useApp()
  const [certs, setCerts] = useState<Certificate[]>([])
  const [dlg, setDlg] = useState<Certificate | 'new' | null>(null)
  const [name, setName] = useState('')
  const [crt, setCrt] = useState('')
  const [key, setKey] = useState('')
  const [err, setErr] = useState('')
  const [del, setDel] = useState<Certificate | null>(null)
  const load = useCallback(() => api.get<Certificate[]>('/certificates').then((c) => setCerts([...c].sort((x, y) => x.not_after.localeCompare(y.not_after)))).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  const open = (c: Certificate | 'new') => { setDlg(c); setName(c === 'new' ? '' : c.name); setCrt(''); setKey(''); setErr('') }
  const save = async () => {
    try {
      if (dlg && dlg !== 'new') await api.put(`/certificates/${dlg.id}`, { name, cert_pem: crt, key_pem: key })
      else await api.post('/certificates', { name, cert_pem: crt, key_pem: key })
      setDlg(null); notify('Certificate saved'); load()
    } catch (e) { setErr(errText(e)) }
  }
  return (
    <>
      <div className="toolbar"><span className="spacer" /><Btn kind="primary" icon="upload" onClick={() => open('new')}>Upload a certificate</Btn></div>
      <section className="panel flush">
        <table className="responsive">
          <thead><tr><th>Certificate</th><th>Covers</th><th className="hide-phone">Used by</th><th className="n">Expires</th><th /></tr></thead>
          <tbody>
            {certs.map((c) => {
              const d = daysLeft(c.not_after)
              return (
                <tr key={c.id}>
                  <td><span className="ident">{c.name}</span><span className="sub truncate">{c.issuer}</span></td>
                  <td className="secondary">{(c.dns_names ?? []).join(', ') || c.subject}</td>
                  <td className="secondary hide-phone">{c.used_by.map((s) => siteName(siteById[s], s)).join(', ') || <span className="muted">No site</span>}</td>
                  <td className="n">{d < 0 ? <Pill tone="neg">Expired</Pill> : d <= 21 ? <Pill tone="warn">In {d} days</Pill> : <span className="num">{dateTime(c.not_after).slice(0, 10)}</span>}</td>
                  <td className="n" style={{ whiteSpace: 'nowrap' }}>
                    <Btn small onClick={() => open(c)}>Replace</Btn>
                    <IconBtn icon="trash" label={`Delete ${c.name}`} onClick={() => setDel(c)} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {!certs.length && <div style={{ padding: 'var(--card-pad)' }}><Empty>No uploaded certificates. Sites use automatic ones unless you upload your own.</Empty></div>}
      </section>
      <Dialog open={!!dlg} wide title={dlg === 'new' ? 'Upload a certificate' : `Replace ${dlg ? dlg.name : ''}`} onClose={() => setDlg(null)}
        footer={<><Btn onClick={() => setDlg(null)}>Cancel</Btn><Btn kind="primary" disabled={!crt || !key} onClick={save}>Save certificate</Btn></>}>
        {err && <p className="notice" role="alert">{err}</p>}
        <Field label="Name" id="cn" hint="Defaults to the certificate’s first name."><input id="cn" className="input" value={name} onChange={(e) => setName(e.target.value)} /></Field>
        <Field label="Certificate with its chain (PEM)" id="cc"><textarea id="cc" className="input code" rows={6} value={crt} onChange={(e) => setCrt(e.target.value)} placeholder="-----BEGIN CERTIFICATE-----" /></Field>
        <Field label="Private key (PEM)" id="ck" hint="Kept on the server; never shown again."><textarea id="ck" className="input code" rows={5} value={key} onChange={(e) => setKey(e.target.value)} placeholder="-----BEGIN PRIVATE KEY-----" /></Field>
      </Dialog>
      <Confirm open={!!del} danger title={`Delete ${del?.name}?`} confirm="Delete certificate" onClose={() => setDel(null)}
        onConfirm={async () => { const c = del!; setDel(null); try { await api.del(`/certificates/${c.id}`); notify('Certificate deleted'); load() } catch (e) { notifyError(e) } }}>
        A certificate still used by a site cannot be deleted; move the site to another certificate first.
      </Confirm>
    </>
  )
}

function Account() {
  const { me, setMe, notify, notifyError } = useApp()
  const [oldPw, setOldPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [pwErr, setPwErr] = useState('')
  const [setup, setSetup] = useState<{ secret: string; qr: string } | null>(null)
  const [code, setCode] = useState('')
  const [offPw, setOffPw] = useState('')
  const [tErr, setTErr] = useState('')
  if (!me || me.kind !== 'user') return <Empty>Signed in with an API token: there is no account to change.</Empty>
  return (
    <section className="panel" style={{ paddingTop: 0, paddingBottom: 0 }}>
      <div className="setting">
        <div><h2>Password</h2><p className="desc">Changing it signs you out everywhere else.</p></div>
        <form style={{ display: 'grid', gap: 16, maxWidth: 420 }} onSubmit={async (e) => {
          e.preventDefault()
          try { await api.post('/auth/password', { old_password: oldPw, new_password: newPw }); setOldPw(''); setNewPw(''); setPwErr(''); notify('Password changed') } catch (er) { setPwErr(errText(er)) }
        }}>
          <Field label="Current password" id="op"><input id="op" className="input" type="password" autoComplete="current-password" value={oldPw} onChange={(e) => setOldPw(e.target.value)} /></Field>
          <Field label="New password" id="np" hint="8 to 72 characters." error={pwErr}><input id="np" className="input" type="password" autoComplete="new-password" value={newPw} onChange={(e) => setNewPw(e.target.value)} aria-describedby="np-hint" /></Field>
          <div><button type="submit" className="btn primary" disabled={!oldPw || newPw.length < 8}>Change password</button></div>
        </form>
      </div>
      <div className="setting">
        <div><h2>Two-step sign-in</h2><p className="desc">After the password, ask for a 6-digit code from an authenticator app.</p></div>
        <div style={{ display: 'grid', gap: 16, maxWidth: 520 }}>
          {tErr && <p className="error-line" role="alert">{tErr}</p>}
          {me.totp_enabled ? (
            <>
              <p><Pill tone="pos">On</Pill></p>
              <Field label="Your password, to turn it off" id="tp"><input id="tp" className="input" type="password" value={offPw} onChange={(e) => setOffPw(e.target.value)} /></Field>
              <div><Btn kind="danger" disabled={!offPw} onClick={async () => {
                try { await api.post('/auth/totp/disable', { password: offPw }); setOffPw(''); setMe({ ...me, totp_enabled: false } as Me); notify('Two-step sign-in is off') } catch (e) { setTErr(errText(e)) }
              }}>Turn off</Btn></div>
            </>
          ) : setup ? (
            <div style={{ display: 'grid', gridTemplateColumns: '180px minmax(0,1fr)', gap: 20, alignItems: 'start' }}>
              <img src={setup.qr} width={180} height={180} alt="Code to scan with an authenticator app" style={{ borderRadius: 4 }} />
              <div style={{ display: 'grid', gap: 12 }}>
                <p>Scan the code, or type this key into the app:</p>
                <p className="code" style={{ wordBreak: 'break-all' }}>{setup.secret}</p>
                <Field label="Code from the app" id="tc"><input id="tc" className="input num" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} /></Field>
                <div><Btn kind="primary" disabled={code.length !== 6} onClick={async () => {
                  try { await api.post('/auth/totp/enable', { code }); setSetup(null); setCode(''); setMe({ ...me, totp_enabled: true }); notify('Two-step sign-in is on') } catch (e) { setTErr(errText(e)) }
                }}>Turn on</Btn></div>
              </div>
            </div>
          ) : (
            <div><Btn onClick={async () => {
              try {
                const r = await api.post<{ secret: string; otpauth_url: string }>('/auth/totp/setup')
                setSetup({ secret: r.secret, qr: await QRCode.toDataURL(r.otpauth_url, { margin: 1, width: 180, color: { dark: '#000000', light: '#ffffff' } }) })
              } catch (e) { notifyError(e) }
            }}>Set up two-step sign-in</Btn></div>
          )}
        </div>
      </div>
    </section>
  )
}

function Tokens() {
  const { notify, notifyError } = useApp()
  const [tokens, setTokens] = useState<Token[]>([])
  const [name, setName] = useState('')
  const [project, setProject] = useState('')
  const [made, setMade] = useState<Token | null>(null)
  const [del, setDel] = useState<Token | null>(null)
  const load = useCallback(() => api.get<Token[]>('/tokens').then(setTokens).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  return (
    <>
      <form className="toolbar" onSubmit={async (e) => {
        e.preventDefault()
        try { setMade(await api.post<Token>('/tokens', { name, project: project.trim() })); setName(''); setProject(''); load() } catch (er) { notifyError(er) }
      }}>
        <input aria-label="Token name" className="input compact" style={{ width: 280 }} placeholder="What will use it, e.g. billing-sync" value={name} onChange={(e) => setName(e.target.value)} />
        <input aria-label="Project (optional)" className="input compact code" style={{ width: 200 }} placeholder="Project ID (optional)" value={project} onChange={(e) => setProject(e.target.value)} />
        <button type="submit" className="btn primary" disabled={!name.trim()}>Create token</button>
        <span className="spacer" />
        <span className="muted">Send it as <span className="code">Authorization: Bearer …</span>. Without a project it can do anything you can; with one, only that project’s sites.</span>
      </form>
      {made && (
        <p className="notice" style={{ marginBottom: 16 }}>
          Copy it now; it is not shown again: <span className="code" style={{ wordBreak: 'break-all' }}>{made.token}</span>
          <IconBtn icon="copy" label="Copy token" onClick={() => { navigator.clipboard?.writeText(made.token ?? ''); notify('Copied') }} />
        </p>
      )}
      <section className="panel flush">
        <table className="responsive">
          <thead><tr><th>Token</th><th>Project</th><th className="n">Created</th><th className="n">Last used</th><th /></tr></thead>
          <tbody>
            {tokens.map((t) => (
              <tr key={t.id}>
                <td className="ident">{t.name}</td>
                <td>{t.project ? <span className="code">{t.project}</span> : <span className="muted">Every site</span>}</td>
                <td className="n num">{dateTime(t.created).slice(0, 10)}</td>
                <td className="n num">{t.last_used ? when(t.last_used) : <span className="muted">Never</span>}</td>
                <td className="n"><Btn small kind="danger" onClick={() => setDel(t)}>Revoke</Btn></td>
              </tr>
            ))}
          </tbody>
        </table>
        {!tokens.length && <div style={{ padding: 'var(--card-pad)' }}><Empty>No API tokens.</Empty></div>}
      </section>
      <Confirm open={!!del} danger title={`Revoke ${del?.name}?`} confirm="Revoke token" onClose={() => setDel(null)}
        onConfirm={async () => { const t = del!; setDel(null); try { await api.del(`/tokens/${t.id}`); notify('Token revoked'); load() } catch (e) { notifyError(e) } }}>
        Anything still using it gets "invalid credentials" from now on.
      </Confirm>
    </>
  )
}

function System() {
  const { system, sites } = useApp()
  if (!system) return null
  const yes = (b: boolean, on: string, off: string) => (b ? <Pill tone="pos">{on}</Pill> : <Pill>{off}</Pill>)
  return (
    <div className="stack">
    <section className="panel">
      <dl className="kv" style={{ rowGap: 14 }}>
        <dt>Engine</dt><dd>{system.engine_ok ? <Pill tone="pos">Running</Pill> : <><Pill tone="neg">Unreachable</Pill> <span className="muted">{system.engine_error}</span></>}</dd>
        <dt>Console version</dt><dd className="num">{system.version}</dd>
        <dt>Manager started</dt><dd className="num">{dateTime(system.started)}</dd>
        <dt>Sites</dt><dd className="num">{sites.length}</dd>
        <dt>Default ports</dt><dd className="num">HTTP {system.http_port}, HTTPS {system.https_port}</dd>
        <dt>Country lookup</dt><dd>{yes(system.geoip, 'On', 'Not set up')} {system.geoip && <span className="muted">IP geolocation by <a href="https://db-ip.com" target="_blank" rel="noreferrer" style={{ textDecoration: 'underline' }}>DB-IP</a>, CC BY 4.0</span>}</dd>
        <dt>Traffic counts</dt><dd>{yes(system.access_log, 'Recorded', 'Off')}</dd>
        <dt>Sites served from files</dt><dd>{yes(system.static_sites, 'Available', 'Not set up')}</dd>
      </dl>
    </section>
    <RulesetPanel />
    <BackupsPanel />
    <AlertsPanel />
    </div>
  )
}

function RulesetPanel() {
  const { notify, notifyError, reloadSystem } = useApp()
  const [sets, setSets] = useState<Rulesets | null>(null)
  const [busy, setBusy] = useState('')
  const load = useCallback(() => api.get<Rulesets>('/rulesets').then(setSets).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  const use = async (version: string, name: string) => {
    setBusy(version || 'builtin')
    try { await api.put('/rulesets/active', { version }); notify(`Now running ${name}`); load(); reloadSystem() } catch (e) { notifyError(e) } finally { setBusy('') }
  }
  return (
    <section className="panel flush" aria-labelledby="ruleset-title">
      <header style={{ padding: 'var(--card-pad) var(--card-pad) 0' }}><h2 id="ruleset-title">Rule set</h2><span className="meta">switching reloads the engine without dropping a connection</span></header>
      <table className="responsive">
        <thead><tr><th>OWASP Core Rule Set</th><th>Source</th><th /></tr></thead>
        <tbody>
          {(sets?.items ?? []).map((r) => (
            <tr key={r.version || 'builtin'}>
              <td className="ident num">{r.name}</td>
              <td className="muted">{r.version ? 'Installed, signature checked' : 'Built into the engine'}</td>
              <td className="n">{r.active ? <Pill tone="pos">Running</Pill>
                : <Btn small disabled={!!busy} onClick={() => use(r.version, r.name)}>{busy === (r.version || 'builtin') ? 'Switching…' : 'Use this'}</Btn>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="muted" style={{ padding: '12px var(--card-pad) var(--card-pad)' }}>
        To add a newer release, run <span className="code">bash scripts/crs-install.sh 4.30.0</span> on the server. It only installs a release signed by the CRS project.
        If the engine can't load a rule set, the switch is refused and the current rules keep running.
      </p>
    </section>
  )
}

function size(n: number) {
  return n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`
}

function BackupsPanel() {
  const { notify, notifyError } = useApp()
  const [list, setList] = useState<Backup[]>([])
  const [busy, setBusy] = useState(false)
  const load = useCallback(() => api.get<Backup[]>('/backups').then(setList).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  return (
    <section className="panel flush" aria-labelledby="backups-title">
      <header style={{ padding: 'var(--card-pad) var(--card-pad) 0' }}>
        <h2 id="backups-title">Database backups</h2>
        <Btn small icon="plus" disabled={busy} onClick={async () => {
          setBusy(true)
          try { const b = await api.post<Backup>('/backups'); notify(`Backup ${b.name} written`); load() } catch (e) { notifyError(e) } finally { setBusy(false) }
        }}>{busy ? 'Backing up…' : 'Back up now'}</Btn>
      </header>
      <table className="responsive">
        <thead><tr><th>File</th><th className="n">Taken</th><th className="n">Size</th><th /></tr></thead>
        <tbody>
          {list.map((b) => (
            <tr key={b.name}>
              <td className="ident num">{b.name}</td>
              <td className="n num">{when(b.created)}</td>
              <td className="n num">{size(b.size)}</td>
              <td className="n">{DEMO ? <span className="muted">Download</span> : <a className="card-link" href={`/api/v1/backups/${b.name}`} download>Download</a>}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {!list.length && <div style={{ padding: '0 var(--card-pad)' }}><Empty>No backups yet. The first one is taken a minute after the manager starts, then once a day.</Empty></div>}
      <p className="muted" style={{ padding: '12px var(--card-pad) var(--card-pad)' }}>
        A backup holds the sites, rules, certificates, users and security events, not the traffic counts. It contains private keys and
        password hashes: keep downloaded copies somewhere safe. To restore, stop the manager and run{' '}
        <span className="code">manager -config /data/manager.json -restore /data/backups/&lt;file&gt;</span>.
      </p>
    </section>
  )
}

function AlertsPanel() {
  const { notify, notifyError } = useApp()
  const [cur, setCur] = useState<Alerts | null>(null)
  const [hook, setHook] = useState('')
  const [beat, setBeat] = useState('')
  const [err, setErr] = useState<{ field?: string; msg: string } | null>(null)
  const load = useCallback(() => api.get<Alerts>('/alerts').then((a) => { setCur(a); setHook(a.webhook_url); setBeat(a.heartbeat_url) }).catch(notifyError), [notifyError])
  useEffect(() => { load() }, [load])
  const dirty = !!cur && (hook !== cur.webhook_url || beat !== cur.heartbeat_url)
  return (
    <section className="panel" aria-labelledby="alerts-title">
      <header><h2 id="alerts-title">Alerts</h2>{cur?.engine_down_since && <Pill tone="neg">Engine down since {dateTime(cur.engine_down_since)}</Pill>}</header>
      <form className="stack" style={{ maxWidth: 640 }} onSubmit={async (e) => {
        e.preventDefault()
        setErr(null)
        try { setCur(await api.put<Alerts>('/alerts', { webhook_url: hook, heartbeat_url: beat })); notify('Alert settings saved') } catch (er) { setErr({ field: (er as { field?: string }).field, msg: errText(er) }) }
      }}>
        <Field id="alert-hook" label="Webhook" error={err?.field === 'webhook_url' ? err.msg : undefined}
          hint="A Slack, Discord or any JSON webhook. It hears when the engine stops answering for a minute, when it is back, and when a backup fails.">
          <input id="alert-hook" className="input" type="url" placeholder="https://hooks.slack.com/services/…" value={hook} onChange={(e) => setHook(e.target.value)} />
        </Field>
        <Field id="alert-beat" label="Heartbeat URL" error={err?.field === 'heartbeat_url' ? err.msg : undefined}
          hint="Pinged every 30 seconds while all is well, for an outside monitor such as Healthchecks.io or Uptime Kuma. It is the only way to hear that this whole server went down.">
          <input id="alert-beat" className="input" type="url" placeholder="https://hc-ping.com/…" value={beat} onChange={(e) => setBeat(e.target.value)} />
        </Field>
        {err && !err.field && <p className="neg-text">{err.msg}</p>}
        <div className="toolbar" style={{ marginBottom: 0 }}>
          <button type="submit" className="btn primary" disabled={!dirty}>Save</button>
          <Btn disabled={!cur?.webhook_url || dirty} onClick={async () => {
            try { await api.post('/alerts/test'); notify('Test alert sent') } catch (e) { notifyError(e) }
          }}>Send a test alert</Btn>
        </div>
      </form>
    </section>
  )
}
