export default function AttackStats({ stats }) {
  if (!stats) return null

  const maxIpCount = Math.max(...(stats.top_attacker_ips || []).map((i) => i.count), 1)

  return (
    <section className="section">
      <h2>Attack Analytics</h2>
      <div className="stats-grid">
        <div className="stats-card">
          <h3>Top Attacker IPs</h3>
          {(stats.top_attacker_ips || []).length === 0 ? (
            <p className="empty">No attackers recorded</p>
          ) : (
            stats.top_attacker_ips.map((item, i) => (
              <div key={i} className="attacker-row">
                <span className="attacker-ip">{item.ip}</span>
                <div className="attacker-bar-container">
                  <div
                    className="attacker-bar"
                    style={{ width: `${(item.count / maxIpCount) * 100}%` }}
                  />
                </div>
                <span className="attacker-count">{item.count}</span>
              </div>
            ))
          )}
        </div>

        <div className="stats-card">
          <h3>Severity Breakdown</h3>
          <div className="severity-grid">
            <div className="severity-item severity-high">
              <span className="severity-number">{stats.severity_breakdown?.high || 0}</span>
              <span className="severity-tag">High</span>
            </div>
            <div className="severity-item severity-medium">
              <span className="severity-number">{stats.severity_breakdown?.medium || 0}</span>
              <span className="severity-tag">Medium</span>
            </div>
            <div className="severity-item severity-low">
              <span className="severity-number">{stats.severity_breakdown?.low || 0}</span>
              <span className="severity-tag">Low</span>
            </div>
          </div>
        </div>

        <div className="stats-card">
          <h3>Attacks by Service</h3>
          {Object.keys(stats.service_breakdown || {}).length === 0 ? (
            <p className="empty">No attacks yet</p>
          ) : (
            Object.entries(stats.service_breakdown)
              .sort((a, b) => b[1] - a[1])
              .map(([svc, count]) => (
                <div key={svc} className="type-row">
                  <span className="type-name">{svc}</span>
                  <span className="type-count">{count}</span>
                </div>
              ))
          )}
        </div>
      </div>
    </section>
  )
}
