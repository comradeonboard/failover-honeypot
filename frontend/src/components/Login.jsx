import { useState } from 'react'

export default function Login({ onSuccess }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (res.ok) {
        const data = await res.json()
        localStorage.setItem('fhm_token', data.token)
        onSuccess()
      } else {
        setError('Access denied // Invalid credentials')
      }
    } catch {
      setError('Connection error // Retry')
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
          <button className="login-btn" type="submit" disabled={loading || !username || !password}>
            {loading ? 'Authenticating' : 'Authenticate'}
          </button>
        </form>
      </div>
    </div>
  )
}
