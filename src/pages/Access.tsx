import { useCallback, useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Ban, GlobalRule, IPGroup } from '../types'
import { Btn, Confirm, Dialog, Empty, Field, IconBtn, Switch, Tabs } from '../ui'
import { clock, siteName, when } from '../util'
import RuleDialog, { matchWords, type RuleValue } from './RuleDialog'

type Tab = 'rules' | 'lists' | 'bans'

export default function Access() {
  const [params, setParams] = useSearchParams()
  const tab = (params.get('tab') as Tab) || 'rules'
  const [counts, setCounts] = useState({ rules: 0, lists: 0, bans: 0 })
  const setCount = useCallback((k: Tab, n: number) => setCounts((c) => (c[k] === n ? c : { ...c, [k]: n })), [])
  return (
    <>
      <div className="title-row">
        <div>
          <h1>Allow &amp; Deny</h1>
          <p className="sub">Who is always let in and who is refused, before any other guard looks at a request.</p>
        </div>
      </div>
      <Tabs value={tab} onChange={(t) => setParams({ tab: t })} tabs={[
        { value: 'rules', label: 'Shared rules', count: counts.rules }, { value: 'lists', label: 'IP lists', count: counts.lists },
        { value: 'bans', label: 'Banned now', count: counts.bans },
      ]} />
      <div hidden={tab !== 'rules'}><Rules onCount={(n) => setCount('rules', n)} /></div>
      <div hidden={tab !== 'lists'}><Lists onCount={(n) => setCount('lists', n)} /></div>
      <div hidden={tab !== 'bans'}><Bans onCount={(n) => setCount('bans', n)} /></div>
    </>
  )
}

function Rules({ onCount }: { onCount: (n: number) => void }) {
  const { siteById, notify, notifyError } = useApp()
  const [rules, setRules] = useState<GlobalRule[]>([])
  const [groups, setGroups] = useState<Record<string, IPGroup>>({})
  const [edit, setEdit] = useState<{ rule?: GlobalRule } | null>(null)
  const [del, setDel] = useState<GlobalRule | null>(null)
  const load = useCallback(() => {
    api.get<GlobalRule[]>('/rules').then((r) => { setRules([...r].sort((a, b) => (a.priority ?? 0) - (b.priority ?? 0))); onCount(r.length) }).catch(notifyError)
    api.get<IPGroup[]>('/ip-groups').then((g) => setGroups(Object.fromEntries(g.map((x) => [x.id, x])))).catch(() => {})
  }, [notifyError, onCount])
  useEffect(() => { load() }, [load])

  const body = (r: RuleValue) => ({ name: r.name, enabled: r.enabled ?? true, action: r.action, sites: r.sites ?? [], ip_groups: r.ip_groups ?? [], not_ip_groups: r.not_ip_groups ?? [], match: r.match, priority: r.priority ?? 0 })
  const toggle = async (r: GlobalRule) => {
    try { await api.put(`/rules/${r.id}`, body({ ...r, enabled: !r.enabled })); load() } catch (e) { notifyError(e) }
  }
  const words = (r: GlobalRule) => {
    const p: string[] = []
    if (r.ip_groups?.length) p.push(`from ${r.ip_groups.map((g) => groups[g]?.name ?? g).join(' or ')}`)
    if (r.not_ip_groups?.length) p.push(`not from ${r.not_ip_groups.map((g) => groups[g]?.name ?? g).join(' or ')}`)
    const m = matchWords(r.match)
    if (m !== 'every request' || !p.length) p.push(m)
    return p.join(', ')
  }

  return (
    <>
      <div className="toolbar">
        <span className="muted">Checked top to bottom on the sites they name, before each site’s own rules. The first match decides.</span>
        <span className="spacer" />
        <Btn kind="primary" icon="plus" onClick={() => setEdit({})}>Add a rule</Btn>
      </div>
      <section className="panel flush">
        <div className="table-wrap">
          <table className="responsive">
            <thead><tr><th>On</th><th>Rule</th><th>Does</th><th>Sites</th><th className="n hide-phone">Changed</th><th /></tr></thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id}>
                  <td style={{ width: 48 }}><Switch label={`${r.name} on`} checked={r.enabled} onChange={() => toggle(r)} /></td>
                  <td style={{ width: '42%' }}><span className="ident">{r.name}</span><span className="sub">{words(r)}</span></td>
                  <td className={r.action === 'allow' ? 'pos-text' : 'neg-text'}>{r.action === 'allow' ? 'Let in' : 'Refuse'}</td>
                  <td className="secondary">{r.sites?.length ? r.sites.map((s) => siteName(siteById[s], s)).join(', ') : 'Every site'}</td>
                  <td className="n num hide-phone muted">{when(r.updated)}</td>
                  <td className="n" style={{ whiteSpace: 'nowrap' }}>
                    <IconBtn icon="edit" label={`Edit ${r.name}`} onClick={() => setEdit({ rule: r })} />
                    <IconBtn icon="trash" label={`Delete ${r.name}`} onClick={() => setDel(r)} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!rules.length && <div style={{ padding: 'var(--card-pad)' }}><Empty>No shared rules. Add one to refuse or let in traffic on several sites at once.</Empty></div>}
      </section>
      {edit && (
        <RuleDialog open shared title={edit.rule ? 'Edit shared rule' : 'Add a shared rule'}
          initial={edit.rule ? { name: edit.rule.name, action: edit.rule.action, match: edit.rule.match, sites: edit.rule.sites, ip_groups: edit.rule.ip_groups, not_ip_groups: edit.rule.not_ip_groups, enabled: edit.rule.enabled, priority: edit.rule.priority }
            : { name: '', action: 'block', match: {}, enabled: true, priority: 0 }}
          onClose={() => setEdit(null)}
          onSubmit={async (v) => {
            if (edit.rule) await api.put(`/rules/${edit.rule.id}`, body(v))
            else await api.post('/rules', body(v))
            setEdit(null); notify('Rule saved'); load()
          }} />
      )}
      <Confirm open={!!del} danger title={`Delete "${del?.name}"?`} confirm="Delete rule" onClose={() => setDel(null)}
        onConfirm={async () => { const r = del!; setDel(null); try { await api.del(`/rules/${r.id}`); notify('Rule deleted'); load() } catch (e) { notifyError(e) } }}>
        Requests it matched go on to the next rule.
      </Confirm>
    </>
  )
}

function Lists({ onCount }: { onCount: (n: number) => void }) {
  const { notify, notifyError } = useApp()
  const [groups, setGroups] = useState<IPGroup[]>([])
  const [dlg, setDlg] = useState<IPGroup | 'new' | null>(null)
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')
  const [ips, setIps] = useState('')
  const [err, setErr] = useState('')
  const [del, setDel] = useState<IPGroup | null>(null)
  const load = useCallback(() => api.get<IPGroup[]>('/ip-groups').then((g) => { setGroups(g); onCount(g.length) }).catch(notifyError), [notifyError, onCount])
  useEffect(() => { load() }, [load])
  const open = (g: IPGroup | 'new') => {
    setDlg(g); setErr('')
    setName(g === 'new' ? '' : g.name); setDesc(g === 'new' ? '' : g.description ?? ''); setIps(g === 'new' ? '' : g.ips.join('\n'))
  }
  const save = async () => {
    const body = { name, description: desc, ips: ips.split(/[\s,;]+/).filter(Boolean) }
    try {
      if (dlg && dlg !== 'new') await api.put(`/ip-groups/${dlg.id}`, body)
      else await api.post('/ip-groups', body)
      setDlg(null); notify('IP list saved'); load()
    } catch (e) { setErr(errText(e)) }
  }
  return (
    <>
      <div className="toolbar">
        <span className="muted">Named sets of addresses, used by shared rules and by each site’s access rules.</span>
        <span className="spacer" />
        <Btn kind="primary" icon="plus" onClick={() => open('new')}>Add an IP list</Btn>
      </div>
      <section className="panel flush">
        <table className="responsive">
          <thead><tr><th>List</th><th className="n">Entries</th><th className="hide-phone">First entries</th><th className="n hide-phone">Changed</th><th /></tr></thead>
          <tbody>
            {groups.map((g) => (
              <tr key={g.id}>
                <td style={{ width: '36%' }}><span className="ident">{g.name}</span>{g.description && <span className="sub">{g.description}</span>}</td>
                <td className="n num">{g.ips.length}</td>
                <td className="hide-phone code muted truncate" style={{ maxWidth: 280 }}>{g.ips.slice(0, 3).join(', ')}{g.ips.length > 3 ? ', …' : ''}</td>
                <td className="n num hide-phone muted">{when(g.updated)}</td>
                <td className="n" style={{ whiteSpace: 'nowrap' }}>
                  <IconBtn icon="edit" label={`Edit ${g.name}`} onClick={() => open(g)} />
                  <IconBtn icon="trash" label={`Delete ${g.name}`} onClick={() => setDel(g)} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!groups.length && <div style={{ padding: 'var(--card-pad)' }}><Empty>No IP lists yet.</Empty></div>}
      </section>
      <Dialog open={!!dlg} title={dlg === 'new' ? 'Add an IP list' : 'Edit IP list'} onClose={() => setDlg(null)}
        footer={<><Btn onClick={() => setDlg(null)}>Cancel</Btn><Btn kind="primary" onClick={save}>Save list</Btn></>}>
        {err && <p className="notice" role="alert">{err}</p>}
        <Field label="Name" id="gn"><input id="gn" className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={64} /></Field>
        <Field label="What it is" id="gd"><input id="gd" className="input" value={desc} onChange={(e) => setDesc(e.target.value)} /></Field>
        <Field label="Addresses" id="gi" hint="One IP or CIDR per line."><textarea id="gi" className="input code" rows={8} value={ips} onChange={(e) => setIps(e.target.value)} /></Field>
      </Dialog>
      <Confirm open={!!del} danger title={`Delete "${del?.name}"?`} confirm="Delete list" onClose={() => setDel(null)}
        onConfirm={async () => { const g = del!; setDel(null); try { await api.del(`/ip-groups/${g.id}`); notify('IP list deleted'); load() } catch (e) { notifyError(e) } }}>
        A list still used by a rule or a site cannot be deleted.
      </Confirm>
    </>
  )
}

function Bans({ onCount }: { onCount: (n: number) => void }) {
  const { siteById, notify, notifyError } = useApp()
  const [bans, setBans] = useState<Record<string, Ban[]>>({})
  const load = useCallback(() => api.get<Record<string, Ban[]>>('/bans').then((b) => { setBans(b); onCount(Object.values(b).flat().length) }).catch(notifyError), [notifyError, onCount])
  useEffect(() => { load() }, [load])
  const rows = Object.entries(bans).flatMap(([site, list]) => list.map((b) => ({ site, ...b })))
  return (
    <>
      <div className="toolbar">
        <span className="muted">Sources a rate limit banned. A ban ends by itself; lift one early if it caught a real visitor.</span>
        <span className="spacer" />
        <Btn icon="refresh" onClick={load}>Refresh</Btn>
      </div>
      <section className="panel flush">
        <table className="responsive">
          <thead><tr><th>Source</th><th>Site</th><th className="n">Until</th><th /></tr></thead>
          <tbody>
            {rows.map((b) => (
              <tr key={b.site + b.ip}>
                <td className="ident num">{b.ip}</td>
                <td className="secondary">{siteName(siteById[b.site], b.site)}</td>
                <td className="n num">{clock(b.until)}</td>
                <td className="n"><Btn small onClick={async () => {
                  try { await api.del(`/bans?site=${encodeURIComponent(b.site)}&ip=${encodeURIComponent(b.ip)}`); notify(`Ban on ${b.ip} lifted`); load() } catch (e) { notifyError(e) }
                }}>Lift ban</Btn></td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <div style={{ padding: 'var(--card-pad)' }}><Empty>Nobody is banned right now.</Empty></div>}
      </section>
    </>
  )
}
