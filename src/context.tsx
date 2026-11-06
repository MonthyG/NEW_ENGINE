import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'
import { api, errText } from './api'
import type { AppProfile, Me, Protection, SiteView, SystemInfo } from './types'

interface AppState {
  me: Me | null
  setMe: (m: Me | null) => void
  sites: SiteView[]
  sitesLoaded: boolean
  siteById: Record<string, SiteView>
  reloadSites: () => Promise<void>
  protections: Protection[]
  apps: AppProfile[]
  system: SystemInfo | null
  reloadSystem: () => void
  notify: (msg: string) => void
  notifyError: (e: unknown) => void
}

const Ctx = createContext<AppState | null>(null)

export function AppProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null)
  const [sites, setSites] = useState<SiteView[]>([])
  const [sitesLoaded, setSitesLoaded] = useState(false)
  const [protections, setProtections] = useState<Protection[]>([])
  const [apps, setApps] = useState<AppProfile[]>([])
  const [system, setSystem] = useState<SystemInfo | null>(null)
  const [toast, setToast] = useState<{ msg: string; error: boolean; key: number } | null>(null)

  const notify = useCallback((msg: string) => setToast({ msg, error: false, key: Date.now() }), [])
  const notifyError = useCallback((e: unknown) => setToast({ msg: errText(e), error: true, key: Date.now() }), [])
  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), toast.error ? 8000 : 3200)
    return () => clearTimeout(t)
  }, [toast])

  const reloadSites = useCallback(async () => {
    try {
      setSites(await api.get<SiteView[]>('/sites'))
      setSitesLoaded(true)
    } catch (e) {
      notifyError(e)
    }
  }, [notifyError])

  const reloadSystem = useCallback(() => { api.get<SystemInfo>('/system').then(setSystem).catch(() => {}) }, [])

  useEffect(() => {
    if (!me) return
    reloadSites()
    api.get<Protection[]>('/protections').then(setProtections).catch(notifyError)
    api.get<AppProfile[]>('/apps').then(setApps).catch(() => {})
    reloadSystem()
    // the engine status in the top bar stays current
    const t = setInterval(reloadSystem, 30_000)
    return () => clearInterval(t)
  }, [me, reloadSites, reloadSystem, notifyError])

  const siteById = useMemo(() => Object.fromEntries(sites.map((s) => [s.id, s])), [sites])

  return (
    <Ctx.Provider value={{ me, setMe, sites, sitesLoaded, siteById, reloadSites, protections, apps, system, reloadSystem, notify, notifyError }}>
      {children}
      {toast && (
        <div key={toast.key} className={'toast' + (toast.error ? ' error' : '')} role={toast.error ? 'alert' : 'status'}>
          {toast.msg}
        </div>
      )}
    </Ctx.Provider>
  )
}

export function useApp(): AppState {
  const v = useContext(Ctx)
  if (!v) throw new Error('useApp outside AppProvider')
  return v
}
