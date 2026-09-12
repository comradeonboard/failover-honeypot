import { useState } from 'react'
import { sfx } from '../lib/sfx'

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState(false)
  const [loading, setLoading] = useState(false)

  const getDeviceId = () => {
    let id = localStorage.getItem('fhm_device_id')
    if (!id) {
      id = typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : `dev-${Date.now()}-${Math.random().toString(36).slice(2)}`
      localStorage.setItem('fhm_device_id', id)
    }
    return id
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (loading || success) return
    setLoading(true)
    setError('')
    sfx.process()
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password, device_id: getDeviceId() }),
      })
      if (res.ok) {
        const data = await res.json()
        localStorage.setItem('fhm_token', data.token)
        sfx.login()
        setSuccess(true)
        setTimeout(onSuccess, 1200)
      } else if (res.status === 429) {
        const data = await res.json().catch(() => null)
        const minutes = Math.max(1, Math.ceil((data?.detail?.retry_after || 600) / 60))
        setError(`Access locked // Try again in ${minutes} minute${minutes === 1 ? '' : 's'}`)
      } else {
        setError('Access denied // Invalid credentials')
      }
      sfx.error()
    } catch {
      setError('Connection error // Retry')
      sfx.error()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-page">
      <div className="login-box">
        <div className="classification">
          <span>FHM // OPS-CONSOLE</span>
          <span>Restricted Access</span>
        </div>
        <div className="login-header">
          <div className="header-tag">Network Intelligence // FHM-01</div>
          <h1>Failover &amp; Honeypot Monitor</h1>
          <p className="login-sub">Authenticate to access the monitoring console</p>
        </div>
        <form className="login-form" onSubmit={handleSubmit}>
          <label className="login-label" htmlFor="fhm-user">Username</label>
          <input
            id="fhm-user"
            className="login-input"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
          />
          <label className="login-label" htmlFor="fhm-pass">Password</label>
          <input
            id="fhm-pass"
            className="login-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
          />
          {error && <div className="login-error">{error}</div>}
          {success && <div className="login-success">Access granted // Welcome {username}</div>}
          <button className="login-btn" type="submit" disabled={loading || success || !username || !password}>
            {success ? 'Access Granted' : loading ? 'Authenticating' : 'Authenticate'}
          </button>
        </form>
      </div>
    </div>
  )
}
