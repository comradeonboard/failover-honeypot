export default function HoneypotAlerts({ alerts, totalAlerts, onClear }) {
  return (
    <section className="section">
      <div className="section-header-row">
        <h2>🍯 Honeypot Alerts</h2>
        <button className="clear-btn" onClick={onClear} disabled={totalAlerts === 0}>
          Clear Alerts
        </button>
      </div>
      <div className="alert-summary">
        Total Alerts: <span className="alert-count">{totalAlerts}</span>
      </div>
      <div className="alert-container">
        {alerts.length === 0 ? (
          <p className="empty">No attacks detected (yet)</p>
        ) : (
          [...alerts]
            .reverse()
            .map((a, i) => (
              <div
                className={`alert-entry severity-border-${a.severity || 'low'}`}
                key={`${a.timestamp}-${i}`}
              >
                <span className="timestamp">
                  {new Date(a.timestamp).toLocaleTimeString()}
                </span>
                <span className={`severity-badge severity-${a.severity || 'low'}`}>
                  {a.severity || 'low'}
                </span>
                <span className="alert-type">🔴 {a.type}</span>
                {a.service && <span className="service-badge">{a.service}</span>}
                <span className="alert-ip">IP: {a.source_ip}</span>
                {a.data && <span className="alert-data">{a.data}</span>}
              </div>
            ))
        )}
      </div>
    </section>
  )
}
