export default function HostsPanel({ hosts }) {
  const list = hosts || []
  const onlineCount = list.filter((h) => h.online).length

  return (
    <section className="section">
      <div className="section-header-row">
        <h2>Host Console</h2>
        <span className="audit-note">
          {onlineCount} active of {list.length}
        </span>
      </div>
      {list.length === 0 ? (
        <p className="empty">No hosts registered</p>
      ) : (
        list.map((h) => {
          const online = h.online
          return (
            <div className="host-entry" key={h.device_id}>
              <span className={`device-dot ${online ? 'online' : 'offline'}`} />
              <div className="host-main">
                <div className="host-row">
                  <span className="host-name">
                    {h.os} {h.device}
                  </span>
                  <span className={`role-badge ${h.role}`}>
                    {h.role === 'main' ? 'Main Server' : 'Second Host'}
                  </span>
                </div>
                <div className="host-row">
                  <span className="host-browser">{h.browser}</span>
                  <span className="host-ip">{h.ip}</span>
                  <span className="host-date">
                    joined {new Date(h.first_login).toLocaleDateString()} · active{' '}
                    {new Date(h.last_seen).toLocaleTimeString()}
                  </span>
                </div>
              </div>
            </div>
          )
        })
      )}
    </section>
  )
}
