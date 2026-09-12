export default function NetworkScan({ network, onScan }) {
  const devices = network?.devices || []
  const scanning = network?.scanning

  return (
    <section className="section">
      <div className="section-header-row">
        <h2>Network Scan</h2>
        <button className="scan-btn" onClick={onScan} disabled={scanning}>
          {scanning ? `Scanning ${network?.progress ?? 0}%` : 'Run Scan'}
        </button>
      </div>
      <div className="scan-meta">
        <span>Subnet: {network?.subnet || '--'}</span>
        <span>Hosts found: {devices.length}</span>
        <span>
          Last scan:{' '}
          {network?.last_scan ? new Date(network.last_scan).toLocaleTimeString() : '--'}
        </span>
      </div>
      <div className="device-container">
        {devices.length === 0 ? (
          <p className="empty">{scanning ? 'Scanning subnet' : 'No hosts discovered'}</p>
        ) : (
          devices.map((d) => (
            <div className={`device-entry status-${d.status}`} key={d.ip}>
              <span className={`device-dot ${d.status}`} />
              <span className="device-ip">{d.ip}</span>
              <span className="device-hostname">{d.hostname || 'unknown'}</span>
              <span className="device-mac">{d.mac || '--:--:--:--:--:--'}</span>
              <span className="device-seen">
                {new Date(d.last_seen).toLocaleTimeString()}
              </span>
            </div>
          ))
        )}
      </div>
    </section>
  )
}
