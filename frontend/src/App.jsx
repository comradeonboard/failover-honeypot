import { useMonitorData } from './hooks/useMonitorData'
import Header from './components/Header'
import StatusSection from './components/StatusSection'
import UptimeLog from './components/UptimeLog'
import HoneypotAlerts from './components/HoneypotAlerts'

export default function App() {
  const { status, events, alerts, totalAlerts, wsConnected, lastUpdated } = useMonitorData()

  return (
    <div className="app">
      <div className="container">
        <Header wsConnected={wsConnected} />
        <StatusSection status={status} />
        <UptimeLog events={events} />
        <HoneypotAlerts alerts={alerts} totalAlerts={totalAlerts} />
        <footer className="footer">
          <p>Last updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : '--:--:--'}</p>
        </footer>
      </div>
    </div>
  )
}
