import { useState } from 'react'
import { useMonitorData } from './hooks/useMonitorData'
import { useSecurityNotifications } from './hooks/useSecurityNotifications'
import { useHashRoute } from './hooks/useHashRoute'
import AlertToasts from './components/AlertToasts'
import Header from './components/Header'
import Sidebar from './components/Sidebar'
import OverviewPage from './pages/OverviewPage'
import NetworkScanPage from './pages/NetworkScanPage'
import SecurityAuditPage from './pages/SecurityAuditPage'
import DefensePage from './pages/DefensePage'
import HoneypotPage from './pages/HoneypotPage'
import AnalyticsPage from './pages/AnalyticsPage'
import UptimeLogPage from './pages/UptimeLogPage'
import SslPage from './pages/SslPage'
import InventoryPage from './pages/InventoryPage'
import ReportsPage from './pages/ReportsPage'

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
    securityHistory,
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

  const [route, navigate] = useHashRoute()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const goToSection = (key) => {
    setSidebarOpen(false)
    navigate(key)
  }

  const renderPage = () => {
    switch (route) {
      case 'network':
        return <NetworkScanPage network={network} onScan={triggerScan} />
      case 'audit':
        return <SecurityAuditPage scans={securityScans} history={securityHistory} onScan={scanWebsite} />
      case 'defense':
        return <DefensePage defense={defense} onBan={banIp} onUnban={unbanIp} />
      case 'honeypot':
        return (
          <HoneypotPage
            services={services}
            alerts={alerts}
            totalAlerts={totalAlerts}
            onToggle={toggleService}
            onClear={clearAlerts}
          />
        )
      case 'analytics':
        return <AnalyticsPage stats={stats} />
      case 'uptime':
        return <UptimeLogPage events={events} />
      case 'ssl':
        return <SslPage />
      case 'inventory':
        return <InventoryPage />
      case 'reports':
        return <ReportsPage />
      default:
        return <OverviewPage status={status} hosts={hosts} />
    }
  }

  return (
    <div className="app">
      <div className="container">
        <div className="classification">
          <span>FHM // OPS-CONSOLE</span>
          <span>Security Monitoring System</span>
        </div>
        <Header wsConnected={wsConnected} onLogout={onLogout} />
        <button className="sidebar-toggle" onClick={() => setSidebarOpen(true)}>
          ☰ Menu
        </button>
        <div className="layout">
          <Sidebar
            current={route}
            onNavigate={goToSection}
            open={sidebarOpen}
            onClose={() => setSidebarOpen(false)}
          />
          <div className="main-content">
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
            {renderPage()}
            <footer className="footer">
              <p>Last update: {lastUpdated ? lastUpdated.toLocaleTimeString() : '--:--:--'}</p>
            </footer>
          </div>
        </div>
        <AlertToasts toasts={toasts} onDismiss={dismissToast} />
      </div>
    </div>
  )
}
