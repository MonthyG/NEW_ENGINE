import { useEffect, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api, qs } from '../api'
import { useApp } from '../context'
import type { Overview, Resolved, SiteView } from '../types'
import { Btn, Empty, Switch } from '../ui'
import { int, seconds, siteName } from '../util'
import { BotEditor, GateEditor, QueueEditor, RateEditor, useSave, type EditorProps } from './guards'

export type GuardKey = 'rate' | 'queue' | 'bot' | 'gate'

type Save = (patch: Record<string, unknown>, ok: string) => unknown

/** One guard, as both the site page and the cross-site policy pages show it. */
export interface GuardDef {
  title: string
  page: string // the policy page's heading, in SafeLine's words
  intro: string
  on: (r: Resolved) => boolean
  summary: (r: Resolved) => ReactNode
  act: string // key in the overview's actions
  stopsLabel: string
  showStops: (r: Resolved) => boolean
  toggle?: (r: Resolved, save: Save, openEditor: () => void) => { checked: boolean; onChange: (v: boolean) => void }
  Editor: (p: EditorProps) => JSX.Element
}

export const guardDefs: Record<GuardKey, GuardDef> = {
  rate: {
    title: 'Rate limits', page: 'Rate limiting',
    intro: 'Bans a source that sends too many requests, threats or errors. Banned sources are listed under Allow & Deny.',
    on: (r) => !!(r.rate_limit.access || r.rate_limit.attack || r.rate_limit.error),
    summary: (r) => {
      const l = r.rate_limit
      const parts = [
        l.access && `${l.access.requests} requests / ${seconds(l.access.window_sec)}`,
        l.attack && `${l.attack.requests} threats / ${seconds(l.attack.window_sec)}`,
        l.error && `${l.error.requests} errors / ${seconds(l.error.window_sec)}`,
      ].filter(Boolean)
      return parts.length ? <>Bans a source after <strong>{parts.join(', ')}</strong></> : 'Off: no source is ever banned.'
    },
    act: 'rate_limit', stopsLabel: 'from banned sources', showStops: () => true,
    Editor: RateEditor,
  },
  queue: {
    title: 'Queue', page: 'Waiting room',
    intro: 'When a site is busy, extra visitors wait in line instead of overloading the origin.',
    on: (r) => r.waiting_room.enabled,
    summary: (r) => (r.waiting_room.enabled ? <>Holds visitors beyond <strong>{int(r.waiting_room.max_active)}</strong> at once</> : 'Off: every visitor goes straight in.'),
    act: 'wait', stopsLabel: 'held in line, 24 h', showStops: (r) => r.waiting_room.enabled,
    toggle: (r, save, openEditor) => ({ checked: r.waiting_room.enabled, onChange: (v) => (v && !r.waiting_room.max_active ? openEditor() : save({ waiting_room: { ...r.waiting_room, enabled: v } }, v ? 'Queue on' : 'Queue off')) }),
    Editor: QueueEditor,
  },
  bot: {
    title: 'Bot check', page: 'Anti-Bot',
    intro: 'Browsers solve a small puzzle before they get in, which stops scripts and crawlers.',
    on: (r) => r.bot_challenge.enabled,
    summary: (r) => (r.bot_challenge.enabled ? <>Browsers prove themselves once an hour; work level <strong>{r.bot_challenge.difficulty}</strong></> : 'Off: scripts and crawlers are not challenged.'),
    act: 'challenge', stopsLabel: 'challenges, 24 h', showStops: (r) => r.bot_challenge.enabled,
    toggle: (r, save) => ({ checked: r.bot_challenge.enabled, onChange: (v) => save({ bot_challenge: { ...r.bot_challenge, enabled: v } }, v ? 'Bot check on' : 'Bot check off') }),
    Editor: BotEditor,
  },
  gate: {
    title: 'Password gate', page: 'Auth',
    intro: 'Visitors sign in with a username and password before they reach the site.',
    on: (r) => r.auth.enabled,
    summary: (r) => (r.auth.enabled ? <>Sign-in for <strong>{r.auth.users.map((u) => u.username).join(', ')}</strong>, kept {seconds(r.auth.session_ttl_sec || 86400)}</> : 'Off: anyone can reach the site.'),
    act: 'auth', stopsLabel: 'sign-in pages, 24 h', showStops: (r) => r.auth.enabled,
    toggle: (r, save, openEditor) => ({ checked: r.auth.enabled, onChange: (v) => (v && !r.auth.users.length ? openEditor() : save({ auth: { ...r.auth, enabled: v, users: r.auth.users } }, v ? 'Password gate on' : 'Password gate off')) }),
    Editor: GateEditor,
  },
}

export function Stage({ k, title, on, summary, stops, stopsLabel, open, onToggleOpen, toggle, children }: {
  k: string; title: string; on: boolean; summary: React.ReactNode; stops?: number; stopsLabel?: string
  open: boolean; onToggleOpen: () => void; toggle?: { checked: boolean; onChange: (v: boolean) => void }; children?: React.ReactNode
}) {
  return (
    <div className={'stage' + (on ? ' on' : '')} id={`stage-${k}`}>
      <div className="rail-line"><span className="node" /></div>
      <div>
        <h3>{title}</h3>
        <div className="summary">{summary}</div>
      </div>
      <div className="side">
        {stops !== undefined && (
          <div className="stops"><div className="figure num">{int(stops)}</div><div className="label">{stopsLabel ?? 'stopped, 24 h'}</div></div>
        )}
        {toggle && <Switch label={`${title} on`} checked={toggle.checked} onChange={toggle.onChange} />}
        <Btn small onClick={onToggleOpen} aria-expanded={open}>{open ? 'Close' : 'Edit'}</Btn>
      </div>
      {open && <div className="editor">{children}</div>}
    </div>
  )
}

function Row({ guard, site, act, open, onToggleOpen }: { guard: GuardKey; site: SiteView; act: Record<string, number>; open: boolean; onToggleOpen: () => void }) {
  const g = guardDefs[guard]
  const r = site.resolved
  const { save } = useSave(site)
  return (
    <Stage k={guard} title={siteName(site)} on={g.on(r)} summary={g.summary(r)}
      stops={g.showStops(r) ? act[g.act] ?? 0 : undefined} stopsLabel={g.stopsLabel} open={open} onToggleOpen={onToggleOpen}
      toggle={g.toggle?.(r, save, () => open || onToggleOpen())}>
      <g.Editor site={site} onDone={onToggleOpen} />
    </Stage>
  )
}

/** A SafeLine-style policy page: one guard, every site, each with its switch and editor. */
export default function Policy({ guard }: { guard: GuardKey }) {
  const { sites, sitesLoaded } = useApp()
  const g = guardDefs[guard]
  const [open, setOpen] = useState<string | null>(null)
  const [acts, setActs] = useState<Record<string, Record<string, number>>>({})
  const ids = sites.map((s) => s.id).join(',')
  useEffect(() => {
    setOpen(null)
    // shortcut: one overview call per site, fine for tens of sites; add a per-guard counts endpoint if there are hundreds
    sites.forEach((s) => api.get<Overview>('/stats/overview' + qs({ site: s.id, range: '24h' }))
      .then((ov) => setActs((a) => ({ ...a, [s.id]: Object.fromEntries((ov.actions ?? []).map((x) => [x.key, x.count])) })))
      .catch(() => {}))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [guard, ids])
  const on = sites.filter((s) => g.on(s.resolved)).length

  return (
    <>
      <div className="title-row">
        <div>
          <h1>{g.page}</h1>
          <p className="sub">{g.intro} On for {on} of {sites.length} site{sites.length === 1 ? '' : 's'}.</p>
        </div>
        {guard === 'rate' && <div className="actions"><Link className="btn" to="/access?tab=bans">Banned now</Link></div>}
      </div>
      {sites.length ? (
        <section className="panel flush" aria-label={`${g.page} on every site`}>
          {sites.map((s) => (
            <Row key={s.id} guard={guard} site={s} act={acts[s.id] ?? {}} open={open === s.id} onToggleOpen={() => setOpen(open === s.id ? null : s.id)} />
          ))}
        </section>
      ) : sitesLoaded && <Empty>No sites yet. <Link className="card-link" to="/sites/new">Add a site</Link></Empty>}
    </>
  )
}
