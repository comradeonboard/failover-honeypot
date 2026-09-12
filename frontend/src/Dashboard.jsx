import { useMonitorData } from './hooks/useMonitorData'
import Header from './components/Header'
import StatusSection from './components/StatusSection'
import NetworkScan from './components/NetworkScan'
import SecurityScanner from './components/SecurityScanner'
import HoneypotServices from './components/HoneypotServices'
import HoneypotAlerts from './components/HoneypotAlerts'
import AttackStats from './components/AttackStats'
import UptimeLog from './components/UptimeLog'

export default function Dashboard({ onLogout }) {
  const {
    status,
    events,
    alerts,
    totalAlerts,
    services,
    stats,
    network,
    securityScans,
    wsConnected,
    lastUpdated,
    toggleService,
    clearAlerts,
    triggerScan,
    scanWebsite,
  } = useMonitorData()

  return (
    <div className="app">
      <div className="container">
        <div className="classification">
          <span>FHM // OPS-CONSOLE</span>
          <span>Security Monitoring System</span>
        </div>
        <Header wsConnected={wsConnected} onLogout={onLogout} />
        <StatusSection status={status} />
        <NetworkScan network={network} onScan={triggerScan} />
        <SecurityScanner scans={securityScans} onScan={scanWebsite} />
        <HoneypotServices services={services} onToggle={toggleService} />
        <HoneypotAlerts alerts={alerts} totalAlerts={totalAlerts} onClear={clearAlerts} />
        <AttackStats stats={stats} />
        <UptimeLog events={events} />
        <footer className="footer">
          <p>Last update: {lastUpdated ? lastUpdated.toLocaleTimeString() : '--:--:--'}</p>
        </footer>
      </div>
    </div>
  )
}
