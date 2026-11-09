import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation } from 'react-router-dom'
import { api, setUnauthorizedHandler } from './api'
import { useApp } from './context'
import type { Me } from './types'
import Shell from './Shell'
import Overview from './pages/Overview'
import Sites from './pages/Sites'
import SiteNew from './pages/SiteNew'
import Site from './pages/Site'
import Threats from './pages/Threats'
import Policy from './pages/Policy'
import Access from './pages/Access'
import Activity from './pages/Activity'
import Settings from './pages/Settings'
import Welcome from './pages/Welcome'

export default function App() {
  const { setMe, customer, sites, sitesLoaded } = useApp()
  const loc = useLocation()
  const [checked, setChecked] = useState(false)

  useEffect(() => {
    // No login page: the portal signs the customer in and authorises the API. We still ask
    // who we are so the UI can show the account; "not authorised yet" just leaves it unset
    // and the dashboard still renders.
    setUnauthorizedHandler(() => setMe(null))
    api.get<Me>('/auth/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecked(true))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!checked) return null
  // A customer with no site yet has not set the WAF up: the manager's own site list is the record.
  if (customer && !sitesLoaded) return null
  if (customer && sites.length === 0 && loc.pathname !== '/welcome') return <Navigate to="/welcome" replace />

  return (
    <Routes>
      <Route element={<Shell />}>
        <Route path="/overview" element={<Overview />} />
        <Route path="/sites" element={<Sites />} />
        <Route path="/sites/new" element={customer ? <Welcome start="setup" inShell /> : <SiteNew />} />
        <Route path="/sites/:id" element={<Site />} />
        <Route path="/threats" element={<Threats />} />
        <Route path="/access" element={<Access />} />
        <Route path="/rate-limiting" element={<Policy guard="rate" />} />
        <Route path="/waiting-room" element={<Policy guard="queue" />} />
        <Route path="/anti-bot" element={<Policy guard="bot" />} />
        <Route path="/password-gate" element={<Policy guard="gate" />} />
        <Route path="/activity" element={<Activity />} />
        <Route path="/settings" element={<Navigate to="/settings/certificates" replace />} />
        <Route path="/settings/:area" element={<Settings />} />
      </Route>
      <Route path="/welcome" element={<Welcome />} />
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  )
}
