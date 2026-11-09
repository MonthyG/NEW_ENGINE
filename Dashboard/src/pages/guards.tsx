// Editors for each stage of a site's guard, in the engine's order. Each saves its own part of the
// site with one PATCH and reports the result.
import { useEffect, useState } from 'react'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { IPGroup, Limit, Rule, SiteView } from '../types'
import { Btn, ChipsInput, Field, IconBtn, Segmented, Switch } from '../ui'
import { seconds } from '../util'
import { AppPicker } from './AppPicker'
import ExclusionDialog, { exclusionWords } from './ExclusionDialog'
import RuleDialog, { matchWords } from './RuleDialog'

export function useSave(site: SiteView, done?: () => void) {
  const { reloadSites, notify } = useApp()
  const [busy, setBusy] = useState(false)
  const [err, setErr] = useState('')
  const save = async (patch: Record<string, unknown>, msg = 'Saved') => {
    setBusy(true)
    setErr('')
    try {
      await api.patch<SiteView>(`/sites/${site.id}`, patch)
      await reloadSites()
      notify(msg)
      done?.()
      return true
    } catch (e) {
      setErr(errText(e))
      return false
    } finally {
      setBusy(false)
    }
  }
  return { busy, err, save }
}

function Foot({ busy, err, onSave, onCancel }: { busy: boolean; err: string; onSave: () => void; onCancel?: () => void }) {
  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
      <Btn kind="primary" disabled={busy} onClick={onSave}>{busy ? 'Saving' : 'Save'}</Btn>
      {onCancel && <Btn onClick={onCancel}>Cancel</Btn>}
      {err && <span className="error-line" role="alert">{err}</span>}
    </div>
  )
}

export interface EditorProps { site: SiteView; onDone: () => void }

// ---------- access rules ----------
export function AccessEditor({ site, onDone }: EditorProps) {
  const a = site.resolved.access
  const [allowIPs, setAllowIPs] = useState(a.allow_ips ?? [])
  const [blockIPs, setBlockIPs] = useState(a.block_ips ?? [])
  const [allowC, setAllowC] = useState(a.allow_countries ?? [])
  const [blockC, setBlockC] = useState(a.block_countries ?? [])
  const [allowG, setAllowG] = useState(a.allow_groups ?? [])
  const [blockG, setBlockG] = useState(a.block_groups ?? [])
  const [rules, setRules] = useState<Rule[]>(a.rules ?? [])
  const [groups, setGroups] = useState<IPGroup[]>([])
  const [editing, setEditing] = useState<number | null>(null)
  const { busy, err, save } = useSave(site, onDone)
  useEffect(() => { api.get<IPGroup[]>('/ip-groups').then(setGroups).catch(() => {}) }, [])

  const groupPick = (label: string, id: string, value: string[], set: (v: string[]) => void) => (
    <Field label={label} id={id}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12 }}>
        {groups.length ? groups.map((g) => (
          <label key={g.id} className="check">
            <input type="checkbox" checked={value.includes(g.id)} onChange={(e) => set(e.target.checked ? [...value, g.id] : value.filter((x) => x !== g.id))} />
            {g.name}
          </label>
        )) : <span className="muted">No IP lists yet (Access, IP lists).</span>}
      </div>
    </Field>
  )

  return (
    <>
      <div className="grid" style={{ gap: 16 }}>
        <div className="span-6"><Field label="Always let through" id="aip" hint="IPs or CIDRs. They skip every later stage."><ChipsInput id="aip" value={allowIPs} onChange={setAllowIPs} placeholder="61.219.11.0/27" /></Field></div>
        <div className="span-6"><Field label="Always refuse" id="bip" hint="IPs or CIDRs."><ChipsInput id="bip" value={blockIPs} onChange={setBlockIPs} placeholder="45.148.10.82" /></Field></div>
        <div className="span-6">{groupPick('IP lists let through', 'ag', allowG, setAllowG)}</div>
        <div className="span-6">{groupPick('IP lists refused', 'bg', blockG, setBlockG)}</div>
        <div className="span-6"><Field label="Only these countries" id="ac" hint="Two-letter codes. Empty means every country."><ChipsInput id="ac" upper value={allowC} onChange={setAllowC} placeholder="TW, JP" /></Field></div>
        <div className="span-6"><Field label="Refuse these countries" id="bc" hint="Two-letter codes."><ChipsInput id="bc" upper value={blockC} onChange={setBlockC} placeholder="KP" /></Field></div>
      </div>
      <div>
        <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 8 }}>
          <span style={{ fontWeight: 500 }}>Rules for this site</span>
          <Btn small icon="plus" onClick={() => setEditing(-1)}>Add a rule</Btn>
        </div>
        <p className="muted" style={{ marginBottom: 8 }}>Checked after the rules shared by every site, top to bottom; the first match decides.</p>
        <div className="rows">
          {rules.length ? rules.map((r, i) => (
            <div key={i} className="row">
              <span className={r.action === 'allow' ? 'pos-text' : 'neg-text'} style={{ width: 64, fontWeight: 500 }}>{r.action === 'allow' ? 'Let in' : 'Refuse'}</span>
              <div className="grow"><div style={{ fontWeight: 500 }}>{r.name || 'Unnamed rule'}</div><div className="muted truncate">{matchWords(r.match)}</div></div>
              <IconBtn icon="edit" label={`Edit ${r.name || 'rule'}`} onClick={() => setEditing(i)} />
              <IconBtn icon="trash" label={`Remove ${r.name || 'rule'}`} onClick={() => setRules(rules.filter((_, j) => j !== i))} />
            </div>
          )) : <span className="muted">No rules of its own.</span>}
        </div>
      </div>
      {editing !== null && (
        <RuleDialog open title={editing < 0 ? 'Add a rule for this site' : 'Edit rule'}
          initial={editing >= 0 ? { name: rules[editing].name ?? '', action: rules[editing].action, match: rules[editing].match } : { name: '', action: 'block', match: {} }}
          onClose={() => setEditing(null)}
          onSubmit={async (v) => {
            const r: Rule = { name: v.name, action: v.action, match: v.match }
            setRules(editing < 0 ? [...rules, r] : rules.map((x, j) => (j === editing ? r : x)))
            setEditing(null)
          }} />
      )}
      <Foot busy={busy} err={err} onCancel={onDone} onSave={() => save({ access: {
        allow_ips: allowIPs, block_ips: blockIPs, allow_countries: allowC, block_countries: blockC, allow_groups: allowG, block_groups: blockG, rules,
        ...(a.block_ips_file ? { block_ips_file: a.block_ips_file } : {}),
      } }, 'Access rules saved')} />
    </>
  )
}

// ---------- rate limits ----------
const limitDefs = [
  { key: 'access', title: 'Request rate', what: 'requests', def: { requests: 120, window_sec: 10, ban_sec: 300 } },
  { key: 'attack', title: 'Attack rate', what: 'stopped threats', def: { requests: 10, window_sec: 60, ban_sec: 1800 } },
  { key: 'error', title: 'Error rate', what: '4xx and 5xx answers', def: { requests: 50, window_sec: 60, ban_sec: 600 } },
] as const
type LKey = (typeof limitDefs)[number]['key']

export function RateEditor({ site, onDone }: EditorProps) {
  const [limits, setLimits] = useState<Record<LKey, Limit | null>>(site.resolved.rate_limit)
  const { busy, err, save } = useSave(site, onDone)
  return (
    <>
      {limitDefs.map((d) => {
        const l = limits[d.key]
        const set = (v: Limit | null) => setLimits({ ...limits, [d.key]: v })
        return (
          <div key={d.key} style={{ display: 'grid', gap: 10 }}>
            <label className="check" style={{ fontWeight: 500 }}>
              <Switch label={d.title} checked={!!l} onChange={(on) => set(on ? { ...d.def } : null)} /> {d.title}
            </label>
            {l && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', paddingLeft: 40 }}>
                <span>Ban a source after</span>
                <input aria-label={`${d.title}: count`} className="input num" style={{ width: 84 }} type="number" min={1} value={l.requests} onChange={(e) => set({ ...l, requests: Number(e.target.value) })} />
                <span>{d.what} in</span>
                <input aria-label={`${d.title}: window in seconds`} className="input num" style={{ width: 84 }} type="number" min={1} value={l.window_sec} onChange={(e) => set({ ...l, window_sec: Number(e.target.value) })} />
                <span>seconds, for</span>
                <input aria-label={`${d.title}: ban in seconds`} className="input num" style={{ width: 96 }} type="number" min={1} value={l.ban_sec} onChange={(e) => set({ ...l, ban_sec: Number(e.target.value) })} />
                <span>seconds ({seconds(l.ban_sec)})</span>
              </div>
            )}
          </div>
        )
      })}
      <Foot busy={busy} err={err} onCancel={onDone} onSave={() => save({ rate_limit: limits }, 'Rate limits saved')} />
    </>
  )
}

// ---------- password gate ----------
export function GateEditor({ site, onDone }: EditorProps) {
  const r = site.resolved.auth
  const [enabled, setEnabled] = useState<boolean>(true) // opening the editor means the gate is wanted
  const [ttl, setTtl] = useState(r.session_ttl_sec || 86400)
  const [users, setUsers] = useState(r.users.map((u) => ({ username: u.username, password: '', existing: true })))
  const { busy, err, save } = useSave(site, onDone)
  return (
    <>
      <label className="check" style={{ fontWeight: 500 }}><Switch label="Password gate" checked={enabled} onChange={setEnabled} /> Ask visitors to sign in first</label>
      <div style={{ display: 'grid', gap: 8 }}>
        {users.map((u, i) => (
          <div key={i} style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(0,1fr) auto', gap: 8 }}>
            <input aria-label="Username" className="input" value={u.username} disabled={u.existing} placeholder="Username"
              onChange={(e) => setUsers(users.map((x, j) => (j === i ? { ...x, username: e.target.value } : x)))} />
            <input aria-label="Password" className="input" type="password" value={u.password} placeholder={u.existing ? 'Unchanged' : 'Password, 6 or more characters'}
              onChange={(e) => setUsers(users.map((x, j) => (j === i ? { ...x, password: e.target.value } : x)))} />
            <IconBtn icon="trash" label={`Remove ${u.username || 'user'}`} onClick={() => setUsers(users.filter((_, j) => j !== i))} />
          </div>
        ))}
        <div><Btn small icon="plus" onClick={() => setUsers([...users, { username: '', password: '', existing: false }])}>Add a person</Btn></div>
      </div>
      <Field label="Stay signed in for" id="ttl">
        <select id="ttl" className="input select" style={{ maxWidth: 240 }} value={ttl} onChange={(e) => setTtl(Number(e.target.value))}>
          {[[3600, '1 hour'], [28800, '8 hours'], [86400, '1 day'], [604800, '7 days'], [2592000, '30 days']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
      </Field>
      <Foot busy={busy} err={err} onCancel={onDone} onSave={() => save({ auth: { enabled, session_ttl_sec: ttl,
        users: users.filter((u) => u.username.trim()).map((u) => (u.password ? { username: u.username.trim(), password: u.password } : { username: u.username.trim() })) } }, 'Password gate saved')} />
    </>
  )
}

// ---------- queue ----------
export function QueueEditor({ site, onDone }: EditorProps) {
  const r = site.resolved.waiting_room
  const [max, setMax] = useState(r.max_active || 200)
  const [ttl, setTtl] = useState(r.session_ttl_sec || 60)
  const { busy, err, save } = useSave(site, onDone)
  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <span>Let</span>
        <input aria-label="Visitors at once" className="input num" style={{ width: 96 }} type="number" min={1} value={max} onChange={(e) => setMax(Number(e.target.value))} />
        <span>visitors in at once; a visitor's place frees up after</span>
        <input aria-label="Idle seconds" className="input num" style={{ width: 84 }} type="number" min={10} value={ttl} onChange={(e) => setTtl(Number(e.target.value))} />
        <span>seconds without a request.</span>
      </div>
      <p className="muted">Everyone else waits on a page that shows their place and refreshes every 5 seconds.</p>
      <Foot busy={busy} err={err} onCancel={onDone} onSave={() => save({ waiting_room: { enabled: true, max_active: max, session_ttl_sec: ttl } }, 'Queue saved')} />
    </>
  )
}

// ---------- bot check ----------
export function BotEditor({ site, onDone }: EditorProps) {
  const [difficulty, setDifficulty] = useState(site.resolved.bot_challenge.difficulty || 4)
  const { busy, err, save } = useSave(site, onDone)
  return (
    <>
      <p>Browsers solve a small proof-of-work once an hour, which takes about {['a moment', 'a moment', 'a moment', 'a second', 'a few seconds', 'up to ten seconds'][difficulty - 1]} on a phone.
        Scripts, crawlers and API clients get a 403, so let their paths through with an access rule.</p>
      <Field label="Work per visitor" id="diff">
        <Segmented label="Work per visitor" value={difficulty} onChange={setDifficulty}
          options={[1, 2, 3, 4, 5, 6].map((d) => ({ value: d, label: d === 4 ? '4 (default)' : String(d) }))} />
      </Field>
      <Foot busy={busy} err={err} onCancel={onDone} onSave={() => save({ bot_challenge: { enabled: true, difficulty } }, 'Bot check saved')} />
    </>
  )
}

// ---------- threat inspection ----------
const levels = [
  { p: 1, label: 'Standard', hint: 'Few false alarms. The right start for any site.' },
  { p: 2, label: 'Strict', hint: 'Catches more; expect to allow a few paths.' },
  { p: 3, label: 'Very strict', hint: 'For sites with little user input.' },
  { p: 4, label: 'Everything', hint: 'Every rule. For testing.' },
]
export function InspectionEditor({ site, onDone }: EditorProps) {
  const { protections } = useApp()
  const w = site.resolved.waf
  const [paranoia, setParanoia] = useState(w.paranoia)
  const [threshold, setThreshold] = useState(w.anomaly_threshold)
  const [prot, setProt] = useState(w.protections)
  const [apps, setApps] = useState(w.apps ?? [])
  const { busy, err, save } = useSave(site, onDone)
  return (
    <>
      <div className="field">
        <span className="label">This site runs</span>
        <p className="muted" style={{ margin: '0 0 8px' }}>Lets the app’s own admin and editor pages work. Everything else stays fully checked.</p>
        <AppPicker value={apps} onChange={setApps} />
      </div>
      <Field label="How strict" id="lvl" hint={levels.find((l) => l.p === paranoia)?.hint}>
        <Segmented label="How strict" value={paranoia} onChange={setParanoia} options={levels.map((l) => ({ value: l.p, label: l.label }))} />
      </Field>
      <Field label="Score that stops a request" id="thr" hint="One serious rule match scores 5. Lower stops sooner.">
        <input id="thr" className="input num" style={{ width: 96 }} type="number" min={1} max={100} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} />
      </Field>
      <div className="field">
        <span className="label">Look for</span>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '8px 16px' }}>
          {protections.map((p) => (
            <label key={p.key} className="check">
              <input type="checkbox" checked={!!prot[p.key]} onChange={(e) => setProt({ ...prot, [p.key]: e.target.checked })} />
              {p.label}
            </label>
          ))}
        </div>
      </div>
      <Foot busy={busy} err={err} onCancel={onDone} onSave={() => save({ waf: { mode: w.mode, paranoia, anomaly_threshold: threshold, protections: prot, apps } }, 'Inspection saved')} />
      <Exceptions site={site} />
    </>
  )
}

// Rule exceptions, added from a false alarm in Threats or by hand. Removing one saves at once.
function Exceptions({ site }: { site: SiteView }) {
  const list = site.resolved.exclusions ?? []
  const [adding, setAdding] = useState(false)
  const { busy, err, save } = useSave(site)
  return (
    <div className="field" style={{ borderTop: '1px solid var(--rule)', paddingTop: 16 }}>
      <span className="label">Rule exceptions</span>
      <p className="muted" style={{ margin: '0 0 8px' }}>
        {list.length ? 'Rules switched off where they raised false alarms.' : 'None. When a rule stops a real visitor, use False alarm on it in Threats.'}
      </p>
      {list.map((e, i) => (
        <div key={i} className="row" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span className="grow"><span className="code">{exclusionWords(e)}</span>{e.note && <span className="muted"> · {e.note}</span>}</span>
          <IconBtn icon="trash" label={`Remove: ${exclusionWords(e)}`} disabled={busy}
            onClick={() => save({ exclusions: list.filter((_, j) => j !== i) }, 'Exception removed')} />
        </div>
      ))}
      <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 8 }}>
        <Btn small onClick={() => setAdding(true)}>Add exception</Btn>
        {err && <span className="error-line" role="alert">{err}</span>}
      </div>
      <ExclusionDialog open={adding} siteId={site.id} rule={0} field="" path="/" onClose={() => setAdding(false)} />
    </div>
  )
}
