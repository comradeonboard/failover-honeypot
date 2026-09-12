import { useState } from 'react'

export default function DefenseShield({ defense, onBan, onUnban }) {
  const [ip, setIp] = useState('')
  const d = defense || {}
  const modules = d.modules || []
  const banned = d.banned || []
  const events = d.events || []

  const handleBan = (e) => {
    e.preventDefault()
    if (!ip.trim()) return
    onBan(ip.trim())
    setIp('')
  }

  return (
    <section className="section">
      <div className="section-header-row">
        <h2>Defensive Protocols</h2>
        <span className="defense-blocked-stat">
          {d.total_blocked_attempts || 0} attack connection(s) dropped
        </span>
      </div>
      <div className="defense-modules">
        {modules.map((m) => (
          <div className="defense-module" key={m.name}>
            <div className="defense-module-name">
              <span className="module-dot" />
              {m.name}
            </div>
            <p className="defense-module-detail">{m.detail}</p>
          </div>
        ))}
      </div>
      <form className="audit-form" onSubmit={handleBan}>
        <input
          className="audit-input"
          type="text"
          placeholder="Manually blacklist an IP, e.g. 203.0.113.7"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
        <button className="scan-btn danger" type="submit" disabled={!ip.trim()}>
          Blacklist
        </button>
      </form>
      {banned.length === 0 ? (
        <p className="empty">Blocklist empty — no IP is currently banned</p>
      ) : (
        <div className="banned-list">
          {banned.map((b) => (
            <div className="banned-row" key={b.ip}>
              <span className="banned-ip">{b.ip}</span>
              <span className="banned-reason">{b.reason}</span>
              <span className={`banned-exp ${b.permanent ? 'perm' : ''}`}>
                {b.permanent
                  ? 'Permanent'
                  : `until ${new Date(b.expires_at * 1000).toLocaleTimeString()}`}
              </span>
              <span className="banned-blocked">{b.blocked_attempts} dropped</span>
              <button className="unban-btn" onClick={() => onUnban(b.ip)}>Unban</button>
            </div>
          ))}
        </div>
      )}
      {events.length > 0 && (
        <div className="defense-events">
          {events.map((ev, i) => (
            <p className="defense-event" key={i}>
              <span className="defense-event-type">{ev.type}</span> {ev.message}
            </p>
          ))}
        </div>
      )}
    </section>
  )
}
