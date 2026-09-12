const PORT_SERVICES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 80: 'http', 443: 'https',
  139: 'netbios', 445: 'smb', 515: 'printer', 554: 'rtsp', 631: 'ipp',
  8000: 'http-alt', 8080: 'http-alt', 8883: 'mqtt', 9100: 'printer',
  3306: 'mysql', 3389: 'rdp', 49152: 'upnp',
}

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
              <div className="device-main">
                <div className="device-row">
                  <span className="device-ip">{d.ip}</span>
                  <span className="device-hostname">{d.hostname || 'unknown'}</span>
                  <span className="device-type">{d.device_type || 'Unknown Device'}</span>
                </div>
                <div className="device-row device-subrow">
                  <span className="device-mac">{d.mac || '--:--:--:--:--:--'}</span>
                  {d.vendor && <span className="device-vendor">{d.vendor}</span>}
                  {(d.open_ports || []).map((p) => (
                    <span className="port-chip" key={p}>
                      {p}/{PORT_SERVICES[p] || 'svc'}
                    </span>
                  ))}
                  <span className="device-seen">
                    seen {new Date(d.last_seen).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  )
}
