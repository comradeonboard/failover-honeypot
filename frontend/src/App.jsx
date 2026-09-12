import { useMonitorData } from './hooks/useMonitorData'
import Header from './components/Header'
import StatusSection from './components/StatusSection'
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
    wsConnected,
    lastUpdated,
    toggleService,
    clearAlerts,
  } = useMonitorData()

  return (
    <div className="app">
      <div className="container">
        <Header wsConnected={wsConnected} />
        <StatusSection status={status} />
        <HoneypotServices services={services} onToggle={toggleService} />
        <HoneypotAlerts alerts={alerts} totalAlerts={totalAlerts} onClear={clearAlerts} />
        <AttackStats stats={stats} />
        <UptimeLog events={events} />
        <footer className="footer">
          <p>Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : '--:--:--'}</p>
        </footer>
      </div>
    </div>
  )
}
