import { useEffect, useRef, useState } from 'react'
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api, DEMO } from './api'
import { useApp } from './context'
import type { SiteCounts } from './types'
import { Btn, Icon, IconBtn, Mark, ThemeToggle } from './ui'
import { int, siteName } from './util'

const groups = [
  { name: 'Watch', pages: [
    { to: '/overview', icon: 'overview', label: 'Overview' },
    { to: '/threats', icon: 'threats', label: 'Threats', count: true },
    { to: '/activity', icon: 'activity', label: 'Activity' },
  ] },
  { name: 'Policy', pages: [
    { to: '/sites', icon: 'sites', label: 'Sites' },
    { to: '/access', icon: 'access', label: 'Allow & Deny' },
    { to: '/rate-limiting', icon: 'flood', label: 'HTTP Flood', children: [
      { to: '/rate-limiting', label: 'Rate limiting' },
      { to: '/waiting-room', label: 'Waiting room' },
    ] },
    { to: '/anti-bot', icon: 'bot', label: 'Anti-Bot' },
    { to: '/password-gate', icon: 'key', label: 'Auth' },
  ] },
  { name: 'System', pages: [{ to: '/settings', icon: 'settings', label: 'Settings' }] },
]
const pageLabel: Record<string, string> = Object.fromEntries(groups.flatMap((g) => g.pages.flatMap((p) =>
  'children' in p && p.children ? p.children.map((c) => [c.to.slice(1), c.label]) : [[p.to.slice(1), p.label]])))
const areaLabel: Record<string, string> = { certificates: 'Certificates', account: 'Your account', tokens: 'API tokens', system: 'System' }

const modeDot: Record<string, string> = { block: 'var(--positive)', detect: 'var(--warning)', off: '#5b5b60' }
const modeWord: Record<string, string> = { block: 'Blocking', detect: 'Watching', off: 'Off' }
const PHONE = '(max-width: 860px)'
const EDGE = DEMO ? 'edge-tpe-01' : window.location.hostname

/** The menu's content: the pages, then every site. Shared by the sidebar and the phone drawer. */
function Menu({ onNavigate, counts }: { onNavigate?: () => void; counts: SiteCounts }) {
  const { sites, me, setMe, system } = useApp()
  const navigate = useNavigate()
  const logout = async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      /* the session may be gone already */
    }
    setMe(null)
    navigate('/login')
  }
  const ordered = [...sites].sort((a, b) => (counts[b.id]?.blocked ?? 0) - (counts[a.id]?.blocked ?? 0) || siteName(a).localeCompare(siteName(b)))
  const threats = Object.values(counts).reduce((n, c) => n + (c.threats ?? 0), 0)
  return (
    <>
      <nav aria-label="Pages">
        {groups.map((g) => (
          <div key={g.name}>
            <div className="nav-group">{g.name}</div>
            {g.pages.map((p) => 'children' in p && p.children ? (
              <details key={p.label} className="nav-sub" open>
                <summary className="drawer-link"><Icon name={p.icon} /><span>{p.label}</span></summary>
                {p.children.map((c) => (
                  <NavLink key={c.to} to={c.to} className="drawer-link sub" onClick={onNavigate}><span>{c.label}</span></NavLink>
                ))}
              </details>
            ) : (
              <NavLink key={p.to} to={p.to} className="drawer-link" onClick={onNavigate}>
                <Icon name={p.icon} />
                <span>{p.label}</span>
                {'count' in p && threats > 0 && <span className="n" title="Threats stopped today">{int(threats)}</span>}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>
      <div className="drawer-section"><span>Sites</span><span className="num">{sites.length}</span></div>
      <ul className="drawer-sites">
        {ordered.map((s) => (
          <li key={s.id}>
            <NavLink to={`/sites/${s.id}`} className="drawer-site" onClick={onNavigate} title={`${siteName(s)}: ${modeWord[s.resolved.waf.mode]}`}>
              <span className="mode-dot" style={{ background: modeDot[s.resolved.waf.mode] }} aria-label={modeWord[s.resolved.waf.mode]} />
              <span className="name">{siteName(s)}</span>
              <span className={'num stops' + ((counts[s.id]?.blocked ?? 0) > 0 ? ' hot' : '')} title="Refused or stopped today">{int(counts[s.id]?.blocked ?? 0)}</span>
            </NavLink>
          </li>
        ))}
      </ul>
      <NavLink to="/sites/new" className="drawer-add" onClick={onNavigate}><Icon name="plus" /> Add a site</NavLink>
      <div className="node-status" aria-label="Edge status">
        <div><span>Edge</span><b>{EDGE}</b></div>
        <div><span>Engine</span><b className={system && !system.engine_ok ? 'bad' : ''}>{system ? (system.engine_ok ? 'running' : 'unreachable') : 'checking'}</b></div>
        <div><span>Rule set</span><b>{system?.ruleset ?? '-'}</b></div>
        <div><span>Console</span><b>v{system?.version ?? '-'}</b></div>
      </div>
      <div className="drawer-foot">
        <span className="muted truncate">Signed in as {me?.username}</span>
        <button type="button" className="card-link" onClick={logout}>Sign out</button>
      </div>
    </>
  )
}

/** On phones the menu opens as a drawer over the page. */
function Drawer({ open, onClose, counts }: { open: boolean; onClose: () => void; counts: SiteCounts }) {
  const ref = useRef<HTMLDialogElement>(null)
  const [closing, setClosing] = useState(false)
  useEffect(() => {
    const d = ref.current
    if (!d) return
    // reopening mid slide-out cancels it (the cleanup below clears the timer)
    if (open) { setClosing(false); if (!d.open) d.showModal(); return }
    if (!d.open) return
    // slide out first, then close; with reduced motion close at once
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) { d.close(); return }
    setClosing(true)
    const t = setTimeout(() => { setClosing(false); d.close() }, 200)
    return () => clearTimeout(t)
  }, [open])
  return (
    <dialog ref={ref} className={'drawer' + (closing ? ' closing' : '')} aria-label="Menu" onClose={onClose} onCancel={(e) => { e.preventDefault(); onClose() }}
      onClick={(e) => { if (e.target === ref.current) onClose() }}>
      <div className="drawer-head">
        <IconBtn icon="close" label="Close the menu" onClick={onClose} />
        <Mark size={22} />
        <span className="product">WAF</span>
      </div>
      {(open || closing) && <Menu onNavigate={onClose} counts={counts} />}
    </dialog>
  )
}

function readHidden(): boolean {
  try {
    return localStorage.getItem('hiwaf.sidebar') === 'hidden'
  } catch {
    return false
  }
}

export default function Shell() {
  const { system, sites, siteById } = useApp()
  const navigate = useNavigate()
  const loc = useLocation()
  const [drawer, setDrawer] = useState(() => DEMO && new URLSearchParams(window.location.hash.split('?')[1]).get('menu') === '1')
  const [hidden, setHidden] = useState(readHidden)
  const [phone, setPhone] = useState(() => window.matchMedia(PHONE).matches)
  useEffect(() => {
    const m = window.matchMedia(PHONE)
    const on = () => setPhone(m.matches)
    m.addEventListener('change', on)
    return () => m.removeEventListener('change', on)
  }, [])
  const [counts, setCounts] = useState<SiteCounts>({})
  useEffect(() => { if (!DEMO || !loc.search.includes('menu=1')) setDrawer(false) }, [loc.pathname, loc.search])
  useEffect(() => { api.get<SiteCounts>('/site-counts').then(setCounts).catch(() => {}) }, [loc.pathname, sites.length])

  const toggle = () => {
    if (window.matchMedia(PHONE).matches) { setDrawer(true); return }
    const next = !hidden
    setHidden(next)
    try { localStorage.setItem('hiwaf.sidebar', next ? 'hidden' : 'shown') } catch { /* per-browser preference only */ }
  }
  const seg = loc.pathname.split('/').filter(Boolean)
  const crumbs = [{ to: `/${seg[0] ?? 'overview'}`, label: pageLabel[seg[0] ?? 'overview'] ?? 'Overview' }]
  if (seg[0] === 'sites' && seg[1]) crumbs.push({ to: loc.pathname, label: seg[1] === 'new' ? 'Add a site' : siteName(siteById[seg[1]], seg[1]) })
  if (seg[0] === 'settings' && seg[1]) crumbs.push({ to: loc.pathname, label: areaLabel[seg[1]] ?? seg[1] })

  return (
    <div className={'app' + (hidden ? ' sidebar-hidden' : '')}>
      <aside className="sidebar" aria-label="Menu">
        <NavLink to="/overview" className="sidebar-brand" aria-label="HostingInside WAF, overview"><Mark size={24} /><span className="product">WAF</span></NavLink>
        <Menu counts={counts} />
      </aside>
      <div className="main-col">
        <header className="topbar">
          <button type="button" className="menu-btn" aria-label={phone ? 'Open the menu' : hidden ? 'Show the menu' : 'Hide the menu'} aria-expanded={phone ? drawer : !hidden} onClick={toggle}>
            <span /><span /><span />
          </button>
          <NavLink to="/overview" className="brand topbar-brand" aria-label="HostingInside WAF, overview"><Mark size={24} /><span className="product">WAF</span></NavLink>
          <nav className="crumbs" aria-label="You are here">
            <span className="hide-s">{EDGE}</span><span className="sep hide-s">/</span>
            {crumbs.map((c, i) => (
              <span key={i} style={{ display: 'contents' }}>
                {i > 0 && <span className="sep">/</span>}
                {i === crumbs.length - 1 ? <b aria-current="page">{c.label}</b> : <NavLink to={c.to}>{c.label}</NavLink>}
              </span>
            ))}
          </nav>
          <span className="env hide-s">{system?.ruleset ?? 'edge'}</span>
          <span className="spacer" />
          <span className={'dot hide-s' + (system && !system.engine_ok ? ' off' : '')} aria-hidden="true" />
          <span className="engine hide-s">{system ? (system.engine_ok ? 'Engine running' : 'Engine unreachable') : 'Checking engine'}</span>
          <ThemeToggle />
          {!loc.pathname.startsWith('/sites/new') && <Btn kind="primary" small icon="plus" onClick={() => navigate('/sites/new')}>Add a site</Btn>}
        </header>
        <main className="canvas">
          <Outlet />
        </main>
      </div>
      <Drawer open={drawer} onClose={() => setDrawer(false)} counts={counts} />
    </div>
  )
}
