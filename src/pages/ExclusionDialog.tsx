// Rule exceptions: switch one CRS rule off where it raised a false alarm, from the narrowest
// scope (one field on one page) to the whole site.
import { useEffect, useState } from 'react'
import { api, errText } from '../api'
import { useApp } from '../context'
import type { Exclusion } from '../types'
import { Btn, Dialog, Field } from '../ui'

// fieldFrom reads the variable a match was found in from Coraza's data line,
// e.g. "Matched Data: v&n found within ARGS:q: null and void" gives ARGS:q.
export function fieldFrom(data?: string): string {
  const m = /found within (?:MATCHED_VARS:)?([A-Z_]+(?::[^\s:]+)?)/.exec(data ?? '')
  return m ? m[1] : ''
}

// pathFrom is the request path without the query, decoded as the engine sees it.
export function pathFrom(uri: string): string {
  const p = uri.split('?')[0] || '/'
  try { return decodeURIComponent(p) } catch { return p }
}

export function exclusionWords(e: Exclusion): string {
  const where = e.path_exact ? ` on ${e.path_exact}` : e.path_prefix ? ` on ${e.path_prefix}*` : ' on every page'
  return `Rule ${e.rule_id} skips ${e.field ? e.field : 'the whole request'}${where}`
}

type Scope = 'field-path' | 'path' | 'field' | 'site'

export default function ExclusionDialog({ open, siteId, rule, msg, field: field0, path: path0, onClose }: {
  open: boolean; siteId: string; rule: number; msg?: string; field: string; path: string; onClose: () => void
}) {
  const { reloadSites, notify } = useApp()
  const [ruleId, setRuleId] = useState('')
  const [scope, setScope] = useState<Scope>('field-path')
  const [field, setField] = useState('')
  const [path, setPath] = useState('')
  const [under, setUnder] = useState(false)
  const [note, setNote] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!open) return
    setRuleId(rule ? String(rule) : '')
    setScope(field0 || !rule ? 'field-path' : 'path')
    setField(field0)
    setPath(path0)
    setUnder(false)
    setNote('')
    setErr('')
  }, [open]) // eslint-disable-line react-hooks/exhaustive-deps

  const withField = scope === 'field-path' || scope === 'field'
  const withPath = scope === 'field-path' || scope === 'path'
  const ex: Exclusion = { rule_id: Number(ruleId) }
  if (withField) ex.field = field.trim()
  if (withPath) ex[under ? 'path_prefix' : 'path_exact'] = path.trim()
  if (note.trim()) ex.note = note.trim()

  const submit = async () => {
    if (!/^\d{6}$/.test(ruleId)) { setErr('Give the six-digit rule number from the threat log, such as 942100.'); return }
    if (withField && !ex.field) { setErr('Name the field, such as ARGS:q.'); return }
    if (withPath && !(ex.path_exact || ex.path_prefix)) { setErr('Name the page, such as /search.'); return }
    setBusy(true)
    try {
      await api.post(`/sites/${siteId}/exclusions`, ex)
      await reloadSites()
      notify(exclusionWords(ex))
      onClose()
    } catch (e) {
      setErr(errText(e))
    } finally {
      setBusy(false)
    }
  }

  const noField = !!rule && !field0
  const options: { value: Scope; label: string; hint: string; off?: boolean }[] = [
    { value: 'field-path', label: 'This field on this page', hint: 'Narrowest. The rule still checks every other field and page.', off: noField },
    { value: 'path', label: 'The whole request on this page', hint: 'For pages that take free text in many fields, like a post editor.' },
    { value: 'field', label: 'This field on every page', hint: 'For a cookie or parameter the whole site uses.', off: noField },
    { value: 'site', label: 'The whole site', hint: 'Widest. The rule stops checking anything on this site.' },
  ]

  return (
    <Dialog open={open} title={rule ? `Stop rule ${rule} raising this false alarm` : 'Add a rule exception'} onClose={onClose}
      footer={<><Btn onClick={onClose}>Cancel</Btn><Btn kind="primary" disabled={busy} onClick={submit}>{busy ? 'Saving' : 'Add exception'}</Btn></>}>
      {err && <p className="notice" role="alert">{err}</p>}
      {msg && <p className="muted" style={{ marginTop: 0 }}>{msg}</p>}
      {!rule && (
        <Field label="Rule" id="exr" hint="The number shown next to the false alarm in Threats.">
          <input id="exr" className="input num" style={{ width: 120 }} inputMode="numeric" maxLength={6} value={ruleId} onChange={(e) => setRuleId(e.target.value.trim())} />
        </Field>
      )}
      <div className="field">
        <span className="label">Switch the rule off for</span>
        <div role="radiogroup" aria-label="Switch the rule off for" style={{ display: 'grid', gap: 8 }}>
          {options.filter((o) => !o.off).map((o) => (
            <label key={o.value} className="check" style={{ alignItems: 'flex-start' }}>
              <input type="radio" name="exscope" checked={scope === o.value} onChange={() => setScope(o.value)} />
              <span><span style={{ display: 'block', fontWeight: 500 }}>{o.label}</span><span className="muted">{o.hint}</span></span>
            </label>
          ))}
        </div>
      </div>
      {withField && (
        <Field label="Field" id="exf" hint="As the engine names it: ARGS:name for a form or query field, REQUEST_COOKIES:name for a cookie.">
          <input id="exf" className="input code" value={field} onChange={(e) => setField(e.target.value)} />
        </Field>
      )}
      {withPath && (
        <Field label="Page" id="exp">
          <input id="exp" className="input code" value={path} onChange={(e) => setPath(e.target.value)} />
          <label className="check" style={{ marginTop: 8 }}><input type="checkbox" checked={under} onChange={(e) => setUnder(e.target.checked)} /> And every page under it</label>
        </Field>
      )}
      <Field label="Note (optional)" id="exn"><input id="exn" className="input" maxLength={200} value={note} onChange={(e) => setNote(e.target.value)} placeholder="Why this is safe" /></Field>
      {scope === 'site' && <p className="notice">Rule {ruleId} will no longer protect any page of this site. Prefer a narrower exception when you can.</p>}
    </Dialog>
  )
}
