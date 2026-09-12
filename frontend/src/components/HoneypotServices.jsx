const SERVICE_TAGS = {
  ssh: 'SSH',
  http: 'WEB',
  ftp: 'FTP',
  telnet: 'TEL',
}

export default function HoneypotServices({ services, onToggle }) {
  return (
    <section className="section">
      <h2>Honeypot Services</h2>
      <p className="section-desc">
        Each service listens for attackers on its port. Toggle a switch to start or stop it live.
      </p>
      <div className="honeypot-services-grid">
        {services.map((service) => (
          <div
            key={service.name}
            className={`honeypot-service-card ${service.running ? 'active' : 'inactive'}`}
          >
            <div className="service-header">
              <span className="service-icon">{SERVICE_TAGS[service.name] || 'SRV'}</span>
              <div className="service-info">
                <h3>{service.name.toUpperCase()}</h3>
                <span className="service-port">Port {service.port} // {service.protocol}</span>
              </div>
              <label className="toggle-switch">
                <input
                  type="checkbox"
                  checked={service.enabled}
                  onChange={() => onToggle(service.name)}
                />
                <span className="toggle-slider"></span>
              </label>
            </div>
            <div className="service-stats">
              <div className="stat">
                <span className="stat-value">{service.total_connections}</span>
                <span className="stat-label">Hits</span>
              </div>
              <div className="stat">
                <span className="stat-value">{service.unique_ips}</span>
                <span className="stat-label">IPs</span>
              </div>
              <div className="stat">
                <span className="stat-value stat-time">
                  {service.last_attack
                    ? new Date(service.last_attack).toLocaleTimeString()
                    : '--'}
                </span>
                <span className="stat-label">Last</span>
              </div>
            </div>
            <div className="service-status">
              <span className={`status-indicator ${service.running ? 'running' : 'stopped'}`} />
              <span>{service.running ? 'Listening' : 'Stopped'}</span>
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}
