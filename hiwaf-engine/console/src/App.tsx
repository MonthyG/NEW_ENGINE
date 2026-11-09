import { useEffect, useState } from 'react'
import { Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { api, setUnauthorizedHandler } from './api'
import { useApp } from './context'
import type { Me } from './types'
import Shell from './Shell'
import Login from './pages/Login'
import Overview from './pages/Overview'
import Sites from './pages/Sites'
import SiteNew from './pages/SiteNew'
import Site from './pages/Site'
import Threats from './pages/Threats'
import Policy from './pages/Policy'
import Access from './pages/Access'
import Activity from './pages/Activity'
import Settings from './pages/Settings'

export default function App() {
  const { me, setMe } = useApp()
  const [checked, setChecked] = useState(false)
  const navigate = useNavigate()
  const loc = useLocation()

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setMe(null)
      navigate('/login', { replace: true, state: { from: window.location.pathname } })
    })
    api.get<Me>('/auth/me')
      .then(setMe)
      .catch(() => setMe(null))
      .finally(() => setChecked(true))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  if (!checked) return null
  if (!me && loc.pathname !== '/login') return <Navigate to="/login" replace state={{ from: loc.pathname }} />

  return (
    <Routes>
      <Route path="/login" element={me ? <Navigate to="/overview" replace /> : <Login />} />
      <Route element={<Shell />}>
        <Route path="/overview" element={<Overview />} />
        <Route path="/sites" element={<Sites />} />
        <Route path="/sites/new" element={<SiteNew />} />
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
      <Route path="*" element={<Navigate to="/overview" replace />} />
    </Routes>
  )
}
