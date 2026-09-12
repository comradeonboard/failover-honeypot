export default function StatusSection({ status }) {
  const { primary_up, backup_up, active } = status

  return (
    <section className="section">
      <h2>Connection Status</h2>
      <div className="status-grid">
        <div className={`status-card ${primary_up ? 'up' : 'down'}`}>
          <div className="status-icon">{primary_up ? '✓' : '✗'}</div>
          <h3>Primary Connection</h3>
          <p>{primary_up ? 'Online' : 'Offline'}</p>
        </div>

        <div className={`status-card ${backup_up ? 'up' : 'down'}`}>
          <div className="status-icon">{backup_up ? '✓' : '✗'}</div>
          <h3>Backup (Hotspot)</h3>
          <p>{backup_up ? 'Available' : 'Unavailable'}</p>
        </div>

        <div className={`status-card active ${active === 'primary' ? 'primary-active' : 'backup-active'}`}>
          <div className="active-label">Active Connection</div>
          <h3>{active ? active.toUpperCase() : '--'}</h3>
          <p>Using {active} network</p>
        </div>
      </div>
    </section>
  )
}
