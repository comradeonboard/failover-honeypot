export default function Header({ wsConnected }) {
  return (
    <header className="header">
      <h1>🔒 Failover &amp; Honeypot Monitor</h1>
      <div className="ws-indicator">
        <span className={`ws-dot ${wsConnected ? 'connected' : 'disconnected'}`} />
        <span>{wsConnected ? 'Live' : 'Connecting...'}</span>
      </div>
    </header>
  )
}
