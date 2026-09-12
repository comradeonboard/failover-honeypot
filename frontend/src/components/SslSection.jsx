import { useState, useEffect } from 'react'
import { apiGet, apiPost, apiDelete } from '../lib/api'

const STATUS_LABEL = {
  valid: 'OK',
  expiring: 'Expiring',
  critical: 'Critical',
  expired: 'Expired',
  error: 'Error',
  pending: 'Checking',
}

export default function SslSection() {
  const [targets, setTargets] = useState([])
  const [host, setHost] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState('')
  const [loaded, setLoaded] = useState(false)

  const load = () => apiGet('/api/ssl').then((d) => setTargets(d.targets)).catch(() => {})

  useEffect(() => {
    load().finally(() => setLoaded(true))
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [])

  const addHost = async (e) => {
    e.preventDefault()
    if (!host.trim() || adding) return
    setAdding(true)
    setError('')
    try {
      await apiPost('/api/ssl', { host })
      setHost('')
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setAdding(false)
    }
  }

  const removeTarget = async (id) => {
    try {
      await apiDelete(`/api/ssl/${id}`)
      await load()
    } catch {}
  }

  return (
    <section className="section">
      <h2>SSL Certificate Tracking</h2>
      <p className="section-desc">
        Monitors TLS certificates for your sites and warns before they expire. Checked every 6 hours.
      </p>
      <form className="ssl-add-form" onSubmit={addHost}>
        <input
          className="ssl-input"
          type="text"
          placeholder="example.com"
          value={host}
          onChange={(e) => setHost(e.target.value)}
        />
        <button className="scan-btn" type="submit" disabled={adding || !host.trim()}>
          {adding ? 'Checking' : 'Track'}
        </button>
      </form>
      {error && <div className="login-error">{error}</div>}
      {loaded && targets.length === 0 ? (
        <p className="empty">No certificates tracked yet — add a site above.</p>
      ) : (
        <div className="ssl-list">
          {targets.map((t) => (
            <div className="ssl-row" key={t.id}>
              <span className="ssl-host">{t.host}</span>
              <span className="ssl-issuer">{t.issuer || '--'}</span>
              <span className="ssl-expires">{t.expires_at || '--'}</span>
              <span className={`ssl-badge ${t.status}`}>
                {t.status === 'valid' || t.status === 'expiring' || t.status === 'critical' || t.status === 'expired'
                  ? `${STATUS_LABEL[t.status]}${t.days_left != null ? ` // ${t.days_left}d` : ''}`
                  : STATUS_LABEL[t.status] || t.status}
              </span>
              <button className="ssl-remove" onClick={() => removeTarget(t.id)} title="Stop tracking">
                ×
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
