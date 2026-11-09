import { useEffect, useRef, useState, type ReactNode } from 'react'
import { flushSync } from 'react-dom'

// ---------- icons: one outline set, 1.5px, drawn for this console ----------

const paths: Record<string, ReactNode> = {
  overview: <><path d="M4 19V11M10 19V5M16 19v-6M22 19H2" /></>,
  sites: <><rect x="3" y="4" width="18" height="6" rx="1.5" /><rect x="3" y="14" width="18" height="6" rx="1.5" /><path d="M7 7h.01M7 17h.01" /></>,
  threats: <><circle cx="12" cy="12" r="8" /><circle cx="12" cy="12" r="3" /><path d="M12 2v4M12 18v4M2 12h4M18 12h4" /></>,
  access: <><path d="M12 3 4 6v5c0 5 3.4 8.7 8 10 4.6-1.3 8-5 8-10V6l-8-3z" /><path d="M9.5 12.5 11.5 14.5 15 10" /></>,
  activity: <><path d="M3 12h4l2.5-6 5 12L17 12h4" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.6 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" /></>,
  logout: <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></>,
  close: <><path d="M18 6 6 18M6 6l12 12" /></>,
  plus: <><path d="M12 5v14M5 12h14" /></>,
  more: <><circle cx="5" cy="12" r="1" /><circle cx="12" cy="12" r="1" /><circle cx="19" cy="12" r="1" /></>,
  refresh: <><path d="M21 12a9 9 0 1 1-2.6-6.4M21 4v5h-5" /></>,
  copy: <><rect x="9" y="9" width="12" height="12" rx="2" /><path d="M5 15H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v1" /></>,
  trash: <><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14" /></>,
  edit: <><path d="M12 20h9M16.5 3.5a2.1 2.1 0 1 1 3 3L7 19l-4 1 1-4z" /></>,
  upload: <><path d="M12 15V3M7 8l5-5 5 5M4 15v4a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-4" /></>,
  flood: <><path d="M2 12h3l2-6 3 12 3-9 2 6 2-3h5" /></>,
  bot: <><rect x="4" y="8" width="16" height="12" rx="3" /><path d="M12 4v4M9 13h.01M15 13h.01M2 14h2M20 14h2" /></>,
  key: <><circle cx="8" cy="15" r="4" /><path d="m10.8 12.2 9.2-9.2M17 6l3 3M14 9l2 2" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  moon: <><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" /></>,
}

export function Icon({ name, title }: { name: keyof typeof paths | string; title?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
      aria-hidden={title ? undefined : true} role={title ? 'img' : undefined} aria-label={title}>
      {paths[name]}
    </svg>
  )
}

/** The mark: the Hosting Inside logo (public/logo.png, the same file as the admin panel's apple-touch.png). */
export function Mark({ size = 26 }: { size?: number }) {
  const w = Math.round(size * 1.5 * 2.61) // logo.png is a 180px square; the artwork is the band y 54-123, about 2.61:1
  return (
    <span role="img" aria-label="Hosting Inside" style={{ display: 'block', width: w, height: Math.round(size * 1.5), overflow: 'hidden', flex: 'none' }}>
      <img src={import.meta.env.BASE_URL + 'logo.png'} alt="" width={w} height={w} style={{ marginTop: Math.round(-0.3 * w), maxWidth: 'none' }} />
    </span>
  )
}

// ---------- controls ----------

export function Btn({ kind, small, icon, children, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  kind?: 'primary' | 'danger' | 'ghost'; small?: boolean; icon?: string
}) {
  const cls = ['btn', kind, small ? 'small' : ''].filter(Boolean).join(' ')
  return (
    <button type="button" className={cls} {...rest}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  )
}

export function IconBtn({ icon, label, ...rest }: React.ButtonHTMLAttributes<HTMLButtonElement> & { icon: string; label: string }) {
  return (
    <button type="button" className="icon-btn" aria-label={label} title={label} {...rest}>
      <Icon name={icon} />
    </button>
  )
}

export type ThemeChoice = 'light' | 'dark' | 'system'
const darkQuery = matchMedia('(prefers-color-scheme: dark)')

export function savedTheme(): ThemeChoice {
  try { const t = localStorage.getItem('theme'); if (t === 'light' || t === 'dark') return t } catch { /* storage blocked */ }
  return 'system'
}

/** Paints the theme; 'system' follows the computer's setting, also when it changes later. Charts redraw on 'themechange'. */
export function applyTheme(choice: ThemeChoice) {
  const paint = () => {
    document.documentElement.dataset.theme = choice === 'system' ? (darkQuery.matches ? 'dark' : 'light') : choice
    window.dispatchEvent(new Event('themechange'))
  }
  darkQuery.onchange = choice === 'system' ? paint : null
  paint()
}

/** Sun/moon button like the customer panel's: the new theme grows out of the button in a circle (View Transitions). */
export function ThemeToggle() {
  const ref = useRef<HTMLButtonElement>(null)
  const [dark, setDark] = useState(() => document.documentElement.dataset.theme === 'dark')
  const flip = async () => {
    const next: ThemeChoice = dark ? 'light' : 'dark'
    const swap = () => {
      try { localStorage.setItem('theme', next) } catch { /* private window: the choice lasts this visit */ }
      applyTheme(next)
      flushSync(() => setDark(next === 'dark'))
    }
    const el = ref.current
    if (!el || !document.startViewTransition || matchMedia('(prefers-reduced-motion: reduce)').matches) { swap(); return }
    try {
      await document.startViewTransition(swap).ready
    } catch {
      return // the browser skipped the animation (e.g. the tab is hidden); the theme has still changed
    }
    const { top, left, width, height } = el.getBoundingClientRect()
    const x = left + width / 2, y = top + height / 2
    const r = Math.hypot(Math.max(left, innerWidth - left), Math.max(top, innerHeight - top))
    document.documentElement.animate(
      { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${r}px at ${x}px ${y}px)`] },
      { duration: 400, easing: 'ease-in-out', pseudoElement: '::view-transition-new(root)' },
    )
  }
  return (
    <button ref={ref} type="button" className="icon-btn" aria-label={dark ? 'Light mode' : 'Dark mode'} title={dark ? 'Light mode' : 'Dark mode'} onClick={flip}>
      <Icon name={dark ? 'sun' : 'moon'} />
    </button>
  )
}

export function Field({ label, hint, error, children, id }: { label: string; hint?: ReactNode; error?: string; children: ReactNode; id?: string }) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      {children}
      {hint && <div className="hint" id={id ? id + '-hint' : undefined}>{hint}</div>}
      {error && <div className="error">{error}</div>}
    </div>
  )
}

export function Segmented<T extends string | number>({ value, options, onChange, label }: {
  value: T; options: { value: T; label: string }[]; onChange: (v: T) => void; label: string
}) {
  return (
    <div className="segmented" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={String(o.value)} type="button" aria-pressed={o.value === value} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  )
}

export function Tabs<T extends string>({ value, tabs, onChange }: {
  value: T; tabs: { value: T; label: string; count?: number }[]; onChange: (v: T) => void
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button key={t.value} type="button" role="tab" aria-selected={t.value === value} onClick={() => onChange(t.value)}>
          {t.label}
          {t.count !== undefined && <span className="count num">{t.count}</span>}
        </button>
      ))}
    </div>
  )
}

export function Switch({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return <input type="checkbox" role="switch" className="switch" aria-label={label} checked={checked} onChange={(e) => onChange(e.target.checked)} />
}

export function Pill({ tone, children }: { tone?: 'pos' | 'neg' | 'warn'; children: ReactNode }) {
  return <span className={'pill' + (tone ? ' ' + tone : '')}>{children}</span>
}

export function ModePill({ mode }: { mode: string }) {
  if (mode === 'block') return <Pill tone="pos">Block</Pill>
  if (mode === 'detect') return <Pill tone="warn">Watch</Pill>
  return <Pill>Off</Pill>
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

/** A native modal dialog: Escape and the backdrop close it, focus returns where it came from. */
export function Dialog({ open, title, onClose, children, footer, wide }: {
  open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean
}) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => {
    const d = ref.current
    if (!d) return
    if (open && !d.open) d.showModal()
    if (!open && d.open) d.close()
  }, [open])
  return (
    <dialog ref={ref} className={wide ? 'wide' : undefined} onClose={onClose} onCancel={(e) => { e.preventDefault(); onClose() }}
      onClick={(e) => { if (e.target === ref.current) onClose() }} aria-label={title}>
      {open && (
        <>
          <div className="dialog-head">
            <h2>{title}</h2>
            <IconBtn icon="close" label="Close" onClick={onClose} />
          </div>
          <div className="dialog-body">{children}</div>
          {footer && <div className="dialog-foot">{footer}</div>}
        </>
      )}
    </dialog>
  )
}

export function Confirm({ open, title, children, confirm, danger, onClose, onConfirm }: {
  open: boolean; title: string; children: ReactNode; confirm: string; danger?: boolean; onClose: () => void; onConfirm: () => void
}) {
  return (
    <Dialog open={open} title={title} onClose={onClose}
      footer={<><Btn onClick={onClose}>Cancel</Btn><Btn kind={danger ? 'danger' : 'primary'} onClick={onConfirm}>{confirm}</Btn></>}>
      <div>{children}</div>
    </Dialog>
  )
}

/** Values typed as chips: Enter, comma, space or leaving the field adds them. */
export function ChipsInput({ id, value, onChange, placeholder, upper, label }: {
  id?: string; value: string[]; onChange: (v: string[]) => void; placeholder?: string; upper?: boolean; label?: string
}) {
  const [input, setInput] = useState('')
  const commit = (raw: string) => {
    const parts = raw.split(/[\s,;]+/).map((x) => (upper ? x.toUpperCase() : x).trim()).filter(Boolean)
    if (parts.length) onChange(Array.from(new Set([...value, ...parts])))
    setInput('')
  }
  return (
    <div className="chips-input" style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center', minHeight: 36, padding: '4px 6px', border: '1px solid var(--control)', borderRadius: 4, background: 'var(--ground)' }}>
      {value.map((v) => (
        <span key={v} className="pill" style={{ height: 24 }}>
          {v}
          <button type="button" aria-label={`Remove ${v}`} onClick={() => onChange(value.filter((x) => x !== v))}
            style={{ border: 0, background: 'none', color: 'var(--muted)', cursor: 'pointer', padding: 0, lineHeight: 1 }}>×</button>
        </span>
      ))}
      <input id={id} aria-label={label} value={input} placeholder={value.length ? '' : placeholder}
        style={{ flex: 1, minWidth: 140, height: 26, border: 0, outline: 0, background: 'transparent', padding: '0 6px' }}
        onChange={(e) => { const v = e.target.value; if (/[\s,;]$/.test(v)) commit(v); else setInput(v) }}
        onKeyDown={(e) => {
          if (e.key === 'Enter') { e.preventDefault(); commit(input) }
          else if (e.key === 'Backspace' && !input && value.length) onChange(value.slice(0, -1))
        }}
        onBlur={() => input && commit(input)} />
    </div>
  )
}

export function Pager({ total, page, size, onPage }: { total: number; page: number; size: number; onPage: (p: number) => void }) {
  if (total <= size) return total ? <div className="stamp" style={{ padding: '12px 0' }}>{total} in total</div> : null
  const from = page * size + 1
  const to = Math.min(total, from + size - 1)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, justifyContent: 'flex-end', padding: '12px 0' }}>
      <span className="stamp num">{from}–{to} of {total}</span>
      <Btn small disabled={page === 0} onClick={() => onPage(page - 1)}>Newer</Btn>
      <Btn small disabled={to >= total} onClick={() => onPage(page + 1)}>Older</Btn>
    </div>
  )
}

export function useInterval(fn: () => void, ms: number, on = true) {
  useEffect(() => {
    if (!on || ms <= 0) return
    const t = setInterval(fn, ms)
    return () => clearInterval(t)
  }, [fn, ms, on])
}
