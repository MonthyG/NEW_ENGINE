import { useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { api, ApiError, errText } from '../api'
import { useApp } from '../context'
import type { Me } from '../types'
import { Mark } from '../ui'

export default function Login() {
  const { setMe } = useApp()
  const navigate = useNavigate()
  const loc = useLocation()
  const [username, setUsername] = useState('admin')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [needCode, setNeedCode] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setErr('')
    try {
      const me = await api.post<Me>('/auth/login', { username, password, ...(needCode ? { totp: code } : {}) })
      setMe(me)
      const from = (loc.state as { from?: string } | null)?.from
      navigate(from && from !== '/login' ? from : '/overview', { replace: true })
    } catch (er) {
      if (er instanceof ApiError && er.body?.totp_required) {
        setErr(needCode ? er.message : '')
        setNeedCode(true)
      } else setErr(errText(er))
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <div className="side">
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}><Mark size={30} /><span style={{ fontWeight: 600 }}>WAF</span></div>
        <p className="big">Every request to your customers' sites passes this edge first.</p>
        <p className="muted">鷹式特網 · HostingInside LTD</p>
      </div>
      <form onSubmit={submit} aria-labelledby="login-title">
        <h1 id="login-title">Sign in</h1>
        {err && <p className="notice" role="alert">{err}</p>}
        {!needCode ? (
          <>
            <div className="field"><label htmlFor="u">Username</label><input id="u" className="input" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} /></div>
            <div className="field"><label htmlFor="p">Password</label><input id="p" className="input" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} /></div>
          </>
        ) : (
          <div className="field">
            <label htmlFor="c">Code from your authenticator app</label>
            <input id="c" className="input num" inputMode="numeric" autoComplete="one-time-code" autoFocus value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))} />
          </div>
        )}
        <button type="submit" className="btn primary" disabled={busy || (!needCode && !password) || (needCode && code.length !== 6)}>{busy ? 'Signing in' : 'Sign in'}</button>
        <p className="muted" style={{ fontSize: 12 }}>Lost the password? On the server: <span className="code">docker exec hiwaf-manager manager -config /data/manager.json -resetadmin</span></p>
      </form>
    </div>
  )
}
