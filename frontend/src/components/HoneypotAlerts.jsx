export default function HoneypotAlerts({ alerts, totalAlerts }) {
  return (
    <section className="section">
      <h2>🍯 Honeypot Alerts</h2>
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
              <div className="alert-entry" key={`${a.timestamp}-${i}`}>
                <span className="timestamp">{new Date(a.timestamp).toLocaleTimeString()}</span>
                <span className="alert-type">🔴 {a.type}</span>
                <span className="alert-ip">IP: {a.source_ip}</span>
              </div>
            ))
        )}
      </div>
    </section>
  )
}
