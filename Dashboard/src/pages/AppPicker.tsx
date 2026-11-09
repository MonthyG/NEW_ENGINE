// App profiles: tick the software a site runs and the engine loads CRS's own exclusions for it,
// so its admins can edit content while visitors stay fully checked.
import { useApp } from '../context'
import type { AppProfile, SiteView } from '../types'
import { pathFrom } from './ExclusionDialog'

export function AppPicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const { apps } = useApp()
  const flip = (k: string, on: boolean) => onChange(on ? [...value, k] : value.filter((x) => x !== k))
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: '10px 16px' }}>
      {apps.map((a) => (
        <label key={a.key} className="check" style={{ alignItems: 'flex-start' }}>
          <input type="checkbox" checked={value.includes(a.key)} onChange={(e) => flip(a.key, e.target.checked)} style={{ marginTop: 2 }} />
          <span><span style={{ fontWeight: 500 }}>{a.label}</span><span className="muted" style={{ display: 'block' }}>{a.summary}</span></span>
        </label>
      ))}
    </div>
  )
}

export function appLabels(keys: string[] | undefined, apps: AppProfile[]): string {
  return (keys ?? []).map((k) => apps.find((a) => a.key === k)?.label ?? k).join(', ')
}

// appHint names the profile a request's path belongs to, when the site doesn't have it on yet.
export function appHint(site: SiteView | undefined, uri: string, apps: AppProfile[]): AppProfile | undefined {
  if (!site) return undefined
  const path = pathFrom(uri)
  const on = site.resolved.waf.apps ?? []
  return apps.find((a) => !on.includes(a.key) && a.paths.some((p) => path.startsWith(p)))
}
