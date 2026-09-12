import { useState, useEffect } from 'react'
import { apiGet, apiPost } from '../lib/api'

export default function DeviceInventory() {
  const [data, setData] = useState({ devices: [], alerts: [], total_known: 0 })
  const [loaded, setLoaded] = useState(false)

  const load = () => apiGet('/api/devices/inventory').then(setData).catch(() => {})

  useEffect(() => {
    load().finally(() => setLoaded(true))
    const interval = setInterval(load, 15000)
    return () => clearInterval(interval)
  }, [])

  const ack = async (id) => {
    await apiPost(`/api/devices/alerts/${id}/ack`).catch(() => {})
    await load()
  }

  const ackAll = async () => {
    await apiPost('/api/devices/alerts/ack-all').catch(() => {})
    await load()
  }

  return (
    <>
      <section className="section">
        <div className="history-head">
          <div>
            <h2>New Device Alerts</h2>
            <p className="section-desc">
              Raised the first time an unknown device appears on your network.
            </p>
          </div>
          {data.alerts.length > 1 && (
            <button className="export-btn" onClick={ackAll}>
              Acknowledge All
            </button>
          )}
        </div>
        {data.alerts.length === 0 ? (
          <p className="empty">
            {loaded ? 'No unknown devices — everything on the network is recognized.' : 'Loading…'}
          </p>
        ) : (
          <div className="device-alert-list">
            {data.alerts.map((a) => (
              <div className="device-alert-row" key={a.id}>
                <span className="alert-new-badge">NEW</span>
                <span className="device-ip">{a.ip}</span>
                <span className="device-hostname">{a.hostname || 'unknown host'}</span>
                <span className="device-vendor">{a.vendor || 'unknown vendor'}</span>
                <span className="timestamp">{new Date(a.detected_at).toLocaleString()}</span>
                <button className="scan-btn" onClick={() => ack(a.id)}>
                  Acknowledge
                </button>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="section">
        <h2>Device Inventory</h2>
        <p className="section-desc">
          {data.total_known} device{data.total_known === 1 ? '' : 's'} known to this network.
          Devices are learned from network scans.
        </p>
        {loaded && data.devices.length === 0 ? (
          <p className="empty">
            Inventory is built from network scans — run one from the Network Scan section.
          </p>
        ) : (
          <div className="inventory-list">
            {data.devices.map((d) => (
              <div className="inventory-row" key={d.ip}>
                <span className="device-ip">{d.ip}</span>
                <span className="device-hostname">{d.hostname || 'unknown host'}</span>
                <span className="device-vendor">{d.vendor || 'unknown vendor'}</span>
                <span className="device-type">{d.device_type || 'unknown'}</span>
                <span className="timestamp">First seen {new Date(d.first_seen).toLocaleString()}</span>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  )
}
