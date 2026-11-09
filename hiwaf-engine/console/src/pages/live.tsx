// The Overview's two live pieces: traffic flowing through the checkpoint line, and the eagle radar of
// threat sources. Both are drawn from the screen's real counts; their motion is CSS transforms only and
// stops under prefers-reduced-motion.
import { useMemo } from 'react'
import type { GroupRow } from '../types'
import { countryName, when } from '../util'

// The checkpoint grid's column widths (styles.css .checkpoints): lead, six stages, origin.
const COLS = [1.2, 1, 1, 1, 1, 1, 1, 1.2]
const centre = (i: number) => {
  const total = COLS.reduce((a, b) => a + b, 0)
  const before = COLS.slice(0, i).reduce((a, b) => a + b, 0)
  return ((before + COLS[i] / 2) / total) * 100
}
const STAGE_COL: Record<string, number> = { deny: 1, rate_limit: 2, auth: 3, wait: 4, challenge: 5, block: 6 }
const DOTS = 18

/** Dots run left to right along the line. A stopped dot ends, in red, at the stage that stopped its
 *  share of requests; the rest reach the origin. Every DOTS-th request stands for one dot. */
export function Flow({ requests, stops, perSecond }: { requests: number; stops: Record<string, number>; perSecond: number }) {
  const dots = useMemo(() => {
    const stopped = Object.entries(stops).filter(([k]) => k in STAGE_COL && k !== 'auth' && k !== 'challenge' && k !== 'wait')
    const totalStopped = stopped.reduce((n, [, v]) => n + v, 0)
    // at least one red dot whenever anything was stopped, so a small share is still seen
    let red = totalStopped ? Math.max(1, Math.round((totalStopped / Math.max(1, requests)) * DOTS * 6)) : 0
    red = Math.min(red, 6)
    const ends: number[] = []
    for (const [k, v] of stopped.sort((a, b) => b[1] - a[1])) {
      const n = Math.max(v ? 1 : 0, Math.round((v / Math.max(1, totalStopped)) * red))
      for (let i = 0; i < n && ends.length < red; i++) ends.push(STAGE_COL[k])
    }
    const speed = Math.max(3.2, Math.min(9, 9 - Math.log10(Math.max(1, perSecond * 10)) * 2)) // busier is faster
    return Array.from({ length: DOTS }, (_, i) => {
      const redIdx = Math.floor((i * ends.length) / DOTS)
      const isRed = ends.length > 0 && i % Math.max(1, Math.floor(DOTS / ends.length)) === 0 && redIdx < ends.length
      const end = isRed ? centre(ends[redIdx]) : 100
      return { key: i, red: isRed, end, dur: (speed * end) / 100, delay: -(i * speed) / DOTS, lane: (i * 7) % 5 }
    })
  }, [requests, stops, perSecond])

  return (
    <div className="flow" aria-hidden="true">
      {COLS.slice(1, -1).map((_, i) => <span key={i} className="gate" style={{ left: `${centre(i + 1)}%` }} />)}
      {dots.map((d) => (
        <span key={d.key} className={'flow-dot' + (d.red ? ' red' : '')}
          style={{ '--end': d.end, '--dur': `${d.dur.toFixed(2)}s`, '--delay': `${d.delay.toFixed(2)}s`, top: `${6 + d.lane * 5}px` } as React.CSSProperties} />
      ))}
    </div>
  )
}

// a stable bearing per country, so a source keeps its place on the radar between visits
function bearing(code: string): number {
  let h = 2166136261
  for (const c of code || '??') h = Math.imul(h ^ c.charCodeAt(0), 16777619)
  return ((h >>> 0) % 360) * (Math.PI / 180)
}

/** The eagle radar: each threat source is a blip. Its angle comes from its country, its distance from
 *  how long ago it last hit (the centre is now, the rim 24 hours ago), its size from its count. */
export function Radar({ sources, watchSites, now = new Date() }: { sources: GroupRow[]; watchSites: Set<string>; now?: Date }) {
  const R = 92
  const blips = sources.slice(0, 12).map((g) => {
    const ageMin = Math.max(0, (now.getTime() - new Date(g.last).getTime()) / 60000)
    const r = 16 + Math.sqrt(Math.min(1, ageMin / 1440)) * (R - 22)
    const a = bearing(g.country) + (g.client_ip.length % 7) * 0.09
    return { g, x: 100 + Math.sin(a) * r, y: 100 - Math.cos(a) * r, size: 2.5 + Math.min(5, Math.log2(1 + g.count)), fresh: ageMin < 15, watched: watchSites.has(g.site_id) }
  })
  const fresh = blips.filter((b) => b.fresh).length
  return (
    <figure className="radar">
      <svg viewBox="0 0 200 200" role="img" aria-label={`Radar of ${sources.length} threat sources; ${fresh} active in the last 15 minutes`}>
        <circle cx="100" cy="100" r={R} className="radar-ground" />
        {[R * 0.33, R * 0.66].map((r) => <circle key={r} cx="100" cy="100" r={r} className="radar-ring" />)}
        <line x1="100" y1={100 - R} x2="100" y2={100 + R} className="radar-ring" />
        <line x1={100 - R} y1="100" x2={100 + R} y2="100" className="radar-ring" />
        <g className="sweep">
          <path d={`M100 100 L100 ${100 - R} A${R} ${R} 0 0 1 ${100 + R * Math.sin(0.75)} ${100 - R * Math.cos(0.75)} Z`} className="sweep-wedge" />
          <line x1="100" y1="100" x2="100" y2={100 - R} className="sweep-line" />
        </g>
        {blips.map((b) => (
          <g key={b.g.site_id + b.g.client_ip}>
            <title>{`${b.g.client_ip}, ${countryName(b.g.country)}: ${b.g.count} ${b.watched ? 'watched' : 'stopped'}, last ${when(b.g.last)}`}</title>
            {b.fresh && <circle cx={b.x} cy={b.y} r={b.size} className={'ping' + (b.watched ? ' watched' : '')} />}
            <circle cx={b.x} cy={b.y} r={b.size} className={'blip' + (b.watched ? ' watched' : '')} />
          </g>
        ))}
        <g transform="translate(86 86) scale(0.875)">
          <path d="M5 23c2.5-9 8.6-15 17.4-15.6 2.4-.2 4.3.9 4.6 2.6.2 1.3-.6 2.3-2 2.8L22 14l2.6 3.3c.5.7-.2 1.6-1 1.3L19 17c-3.3 1.2-6.5 3.4-9.4 6.6z" fill="#0069a8" />
          <circle cx="21.2" cy="11.4" r="1.25" fill="#ffffff" />
        </g>
      </svg>
      <figcaption className="muted">Centre is now, the rim 24 hours ago. Red was stopped, amber let through in Watch.</figcaption>
    </figure>
  )
}
