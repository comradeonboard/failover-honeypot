import { useMonitorData } from './hooks/useMonitorData'
import { useSecurityNotifications } from './hooks/useSecurityNotifications'
import AlertToasts from './components/AlertToasts'
import Header from './components/Header'
import StatusSection from './components/StatusSection'
import HostsPanel from './components/HostsPanel'
import NetworkScan from './components/NetworkScan'
import SecurityScanner from './components/SecurityScanner'
import DefenseShield from './components/DefenseShield'
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
    defense,
    hosts,
    wsConnected,
    lastUpdated,
    toggleService,
    clearAlerts,
    triggerScan,
    scanWebsite,
    banIp,
    unbanIp,
  } = useMonitorData()

  const { permission, requestPermission, toasts, dismissToast } = useSecurityNotifications(
    alerts,
    defense
  )

  return (
    <div className="app">
      <div className="container">
        <div className="classification">
          <span>FHM // OPS-CONSOLE</span>
          <span>Security Monitoring System</span>
        </div>
        <Header wsConnected={wsConnected} onLogout={onLogout} />
        {permission !== 'granted' && (
          <div className="notify-bar">
            <span>
              Real-time intrusion notifications: {permission === 'denied' ? 'blocked by browser' : 'off'}
            </span>
            {permission !== 'denied' && (
              <button className="notify-btn" onClick={requestPermission}>
                Enable
              </button>
            )}
          </div>
        )}
        <StatusSection status={status} />
        <HostsPanel hosts={hosts} />
        <NetworkScan network={network} onScan={triggerScan} />
        <SecurityScanner scans={securityScans} onScan={scanWebsite} />
        <DefenseShield defense={defense} onBan={banIp} onUnban={unbanIp} />
        <HoneypotServices services={services} onToggle={toggleService} />
        <HoneypotAlerts alerts={alerts} totalAlerts={totalAlerts} onClear={clearAlerts} />
        <AttackStats stats={stats} />
        <UptimeLog events={events} />
        <footer className="footer">
          <p>Last update: {lastUpdated ? lastUpdated.toLocaleTimeString() : '--:--:--'}</p>
        </footer>
        <AlertToasts toasts={toasts} onDismiss={dismissToast} />
      </div>
    </div>
  )
}
