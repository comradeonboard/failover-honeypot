const SECTIONS = [
  { key: 'overview', label: 'Overview' },
  { key: 'network', label: 'Network Scan' },
  { key: 'audit', label: 'Security Audit' },
  { key: 'defense', label: 'Defense Shield' },
  { key: 'honeypot', label: 'Honeypot' },
  { key: 'analytics', label: 'Analytics' },
  { key: 'uptime', label: 'Uptime Log' },
  { key: 'ssl', label: 'SSL Certs' },
  { key: 'inventory', label: 'Inventory' },
  { key: 'reports', label: 'Reports' },
  { key: 'assistant', label: 'AI Assistant' },
]

export default function Sidebar({ current, onNavigate, open, onClose }) {
  return (
    <>
      <div
        className={`sidebar-backdrop ${open ? 'open' : ''}`}
        onClick={onClose}
        aria-hidden="true"
      />
      <aside className={`sidebar ${open ? 'open' : ''}`}>
        <div className="sidebar-label">Sections</div>
        {SECTIONS.map((item) => (
          <button
            key={item.key}
            className={`sidebar-item ${current === item.key ? 'active' : ''}`}
            onClick={() => onNavigate(item.key)}
          >
            {item.label}
          </button>
        ))}
      </aside>
    </>
  )
}
