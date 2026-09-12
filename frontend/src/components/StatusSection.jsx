export default function StatusSection({ status }) {
  const { primary_up, backup_up, active } = status

  return (
    <section className="section">
      <h2>Connection Status</h2>
      <div className="status-grid">
        <div className={`status-card ${primary_up ? 'up' : 'down'}`}>
          <div className="card-label">Primary Uplink</div>
          <div className="status-value">{primary_up ? 'ONLINE' : 'OFFLINE'}</div>
          <div className="card-sub">Target: 8.8.8.8 // interval 5s</div>
        </div>

        <div className={`status-card ${backup_up ? 'up' : 'down'}`}>
          <div className="card-label">Backup Hotspot</div>
          <div className="status-value">{backup_up ? 'STANDBY' : 'NO LINK'}</div>
          <div className="card-sub">Failover interface</div>
        </div>

        <div className="status-card active">
          <div className="card-label">Active Route</div>
          <div className="status-value">{active ? active.toUpperCase() : '--'}</div>
          <div className="card-sub">{active === 'primary' ? 'Primary network in use' : 'Backup network in use'}</div>
        </div>
      </div>
    </section>
  )
}
