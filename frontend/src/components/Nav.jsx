const NAV_ITEMS = [
  { key: 'overview', label: 'Overview' },
  { key: 'network', label: 'Network Scan' },
  { key: 'audit', label: 'Security Audit' },
  { key: 'defense', label: 'Defense Shield' },
  { key: 'honeypot', label: 'Honeypot' },
  { key: 'analytics', label: 'Analytics' },
  { key: 'uptime', label: 'Uptime Log' },
]

export default function Nav({ current, onNavigate }) {
  return (
    <nav className="nav-bar">
      {NAV_ITEMS.map((item) => (
        <button
          key={item.key}
          className={`nav-item ${current === item.key ? 'active' : ''}`}
          onClick={() => onNavigate(item.key)}
        >
          {item.label}
        </button>
      ))}
    </nav>
  )
}
