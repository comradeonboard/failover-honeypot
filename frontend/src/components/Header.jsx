export default function Header({ wsConnected, onLogout }) {
  return (
    <header className="header">
      <div>
        <div className="header-tag">Network Intelligence // FHM-01</div>
        <h1>Failover &amp; Honeypot Monitor</h1>
      </div>
      <div className="header-controls">
        <div className={`ws-indicator ${wsConnected ? 'online' : 'offline'}`}>
          <span className="ws-dot" />
          <span>{wsConnected ? 'Link Active' : 'Link Down'}</span>
        </div>
        <button className="logout-btn" onClick={onLogout}>
          Logout
        </button>
      </div>
    </header>
  )
}
