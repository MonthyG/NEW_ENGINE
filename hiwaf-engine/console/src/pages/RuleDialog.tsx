import { useEffect, useState } from 'react'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { IPGroup, KV, Match } from '../types'
import { Btn, ChipsInput, Dialog, Field, Segmented } from '../ui'
import { siteName } from '../util'

export function matchWords(m: Match): string {
  const p: string[] = []
  if (m.ip?.length) p.push(`from ${m.ip.join(', ')}`)
  if (m.not_ip?.length) p.push(`not from ${m.not_ip.join(', ')}`)
  if (m.country?.length) p.push(`country ${m.country.join(', ')}`)
  if (m.method?.length) p.push(m.method.join('/'))
  if (m.path_exact) p.push(`path is ${m.path_exact}`)
  if (m.path_prefix) p.push(`path starts ${m.path_prefix}`)
  if (m.path_regex) p.push(`path matches ${m.path_regex}`)
  if (m.host) p.push(`host ${m.host}`)
  if (m.header) p.push(`header ${m.header.name} ${m.header.regex ? 'matches ' + m.header.regex : 'has ' + m.header.contains}`)
  if (m.query) p.push(`query ${m.query.name} ${m.query.regex ? 'matches ' + m.query.regex : 'has ' + m.query.contains}`)
  return p.join(', ') || 'every request'
}

export interface RuleValue {
  name: string; action: 'allow' | 'block'; match: Match
  sites?: string[]; ip_groups?: string[]; not_ip_groups?: string[]; enabled?: boolean; priority?: number
}

type PathMode = 'any' | 'exact' | 'prefix' | 'regex'

export default function RuleDialog({ open, title, initial, shared, onClose, onSubmit }: {
  open: boolean; title: string; initial: RuleValue; shared?: boolean; onClose: () => void; onSubmit: (v: RuleValue) => Promise<void>
}) {
  const { sites } = useApp()
  const [v, setV] = useState<RuleValue>(initial)
  const [pathMode, setPathMode] = useState<PathMode>('any')
  const [path, setPath] = useState('')
  const [hdr, setHdr] = useState<{ name: string; value: string; regex: boolean }>({ name: '', value: '', regex: false })
  const [groups, setGroups] = useState<IPGroup[]>([])
  const [err, setErr] = useState('')

  useEffect(() => {
    if (!open) return
    setV(initial)
    const m = initial.match
    setPathMode(m.path_exact ? 'exact' : m.path_prefix ? 'prefix' : m.path_regex ? 'regex' : 'any')
    setPath(m.path_exact || m.path_prefix || m.path_regex || '')
    setHdr({ name: m.header?.name ?? '', value: m.header?.regex || m.header?.contains || '', regex: !!m.header?.regex })
    setErr('')
    if (shared) api.get<IPGroup[]>('/ip-groups').then(setGroups).catch(() => {})
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  const set = (p: Partial<Match>) => setV({ ...v, match: { ...v.match, ...p } })
  const submit = async () => {
    const m: Match = { ...v.match }
    delete m.path_exact; delete m.path_prefix; delete m.path_regex; delete m.header
    if (pathMode !== 'any' && path) m[pathMode === 'exact' ? 'path_exact' : pathMode === 'prefix' ? 'path_prefix' : 'path_regex'] = path
    if (hdr.name && hdr.value) m.header = (hdr.regex ? { name: hdr.name, regex: hdr.value } : { name: hdr.name, contains: hdr.value }) as KV
    for (const k of ['ip', 'not_ip', 'country', 'method'] as const) if (m[k] && !m[k]!.length) delete m[k]
    if (!m.host) delete m.host
    if (!v.name.trim()) { setErr('Give the rule a name; it appears in the activity log.'); return }
    try {
      await onSubmit({ ...v, name: v.name.trim(), match: m })
    } catch (e) {
      setErr(errText(e))
    }
  }

  return (
    <Dialog open={open} title={title} onClose={onClose} wide
      footer={<><Btn onClick={onClose}>Cancel</Btn><Btn kind="primary" onClick={submit}>Save rule</Btn></>}>
      {err && <p className="notice" role="alert">{err}</p>}
      <div className="grid" style={{ gap: 16 }}>
        <div className="span-8"><Field label="Name" id="rn"><input id="rn" className="input" maxLength={64} value={v.name} onChange={(e) => setV({ ...v, name: e.target.value })} placeholder="Refuse the scanner network" /></Field></div>
        <div className="span-4"><Field label="When it matches" id="ra">
          <Segmented label="When it matches" value={v.action} onChange={(a) => setV({ ...v, action: a })} options={[{ value: 'block', label: 'Refuse' }, { value: 'allow', label: 'Let in' }]} />
        </Field></div>
      </div>
      {v.action === 'allow' && <p className="notice">Let in skips rate limits, the bot check and threat inspection. It must name an IP or a path, and never matches paths with ".." or ";".</p>}
      {shared && (
        <div className="grid" style={{ gap: 16 }}>
          <div className="span-8"><Field label="Sites" id="rs" hint="None ticked means every site.">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 16px' }}>
              {sites.map((s) => (
                <label key={s.id} className="check"><input type="checkbox" checked={(v.sites ?? []).includes(s.id)}
                  onChange={(e) => setV({ ...v, sites: e.target.checked ? [...(v.sites ?? []), s.id] : (v.sites ?? []).filter((x) => x !== s.id) })} />{siteName(s)}</label>
              ))}
            </div>
          </Field></div>
          <div className="span-4"><Field label="Order" id="rp" hint="Lower runs first."><input id="rp" className="input num" type="number" value={v.priority ?? 0} onChange={(e) => setV({ ...v, priority: Number(e.target.value) })} /></Field></div>
        </div>
      )}
      <div className="grid" style={{ gap: 16 }}>
        <div className="span-6"><Field label="Source IP or CIDR" id="ri"><ChipsInput id="ri" value={v.match.ip ?? []} onChange={(x) => set({ ip: x })} /></Field></div>
        <div className="span-6"><Field label="Source is not" id="rni"><ChipsInput id="rni" value={v.match.not_ip ?? []} onChange={(x) => set({ not_ip: x })} /></Field></div>
        {shared && groups.length > 0 && (
          <div className="span-12"><Field label="Source in IP list" id="rg">
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 16px' }}>
              {groups.map((g) => (
                <label key={g.id} className="check"><input type="checkbox" checked={(v.ip_groups ?? []).includes(g.id)}
                  onChange={(e) => setV({ ...v, ip_groups: e.target.checked ? [...(v.ip_groups ?? []), g.id] : (v.ip_groups ?? []).filter((x) => x !== g.id) })} />{g.name}</label>
              ))}
            </div>
          </Field></div>
        )}
        <div className="span-6"><Field label="Country" id="rc" hint="Two-letter codes."><ChipsInput id="rc" upper value={v.match.country ?? []} onChange={(x) => set({ country: x })} /></Field></div>
        <div className="span-6"><Field label="Method" id="rm"><ChipsInput id="rm" upper value={v.match.method ?? []} onChange={(x) => set({ method: x })} placeholder="POST" /></Field></div>
        <div className="span-4"><Field label="Path" id="rpm">
          <select id="rpm" className="input select" value={pathMode} onChange={(e) => setPathMode(e.target.value as PathMode)}>
            <option value="any">Any path</option><option value="exact">Is exactly</option><option value="prefix">Starts with</option><option value="regex">Matches the pattern</option>
          </select>
        </Field></div>
        <div className="span-8"><Field label="Path value" id="rpv"><input id="rpv" className="input" disabled={pathMode === 'any'} value={path} onChange={(e) => setPath(e.target.value)} placeholder="/wp-login.php" /></Field></div>
        <div className="span-4"><Field label="Header" id="rh"><input id="rh" className="input" value={hdr.name} onChange={(e) => setHdr({ ...hdr, name: e.target.value })} placeholder="User-Agent" /></Field></div>
        <div className="span-8"><Field label="Header value" id="rhv" hint={<label className="check"><input type="checkbox" checked={hdr.regex} onChange={(e) => setHdr({ ...hdr, regex: e.target.checked })} />Treat as a pattern</label>}>
          <input id="rhv" className="input" value={hdr.value} onChange={(e) => setHdr({ ...hdr, value: e.target.value })} placeholder="sqlmap" />
        </Field></div>
      </div>
    </Dialog>
  )
}
