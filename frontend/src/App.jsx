import { useMonitorData } from './hooks/useMonitorData'
import Header from './components/Header'
import StatusSection from './components/StatusSection'
import NetworkScan from './components/NetworkScan'
import HoneypotServices from './components/HoneypotServices'
import HoneypotAlerts from './components/HoneypotAlerts'
import AttackStats from './components/AttackStats'
import UptimeLog from './components/UptimeLog'

export default function App() {
  const {
    status,
    events,
    alerts,
    totalAlerts,
    services,
    stats,
    network,
    wsConnected,
    lastUpdated,
    toggleService,
    clearAlerts,
    triggerScan,
  } = useMonitorData()

  return (
    <div className="app">
      <div className="container">
        <div className="classification">
          <span>FHM // OPS-CONSOLE</span>
          <span>Security Monitoring System</span>
        </div>
        <Header wsConnected={wsConnected} />
        <StatusSection status={status} />
        <NetworkScan network={network} onScan={triggerScan} />
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
