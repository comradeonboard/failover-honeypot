import { useState, useRef, useEffect } from 'react'

const PRIMARY_ITEMS = [
  { key: 'overview', label: 'Overview' },
  { key: 'network', label: 'Network Scan' },
  { key: 'audit', label: 'Security Audit' },
  { key: 'honeypot', label: 'Honeypot' },
]

const MENU_ITEMS = [
  { key: 'defense', label: 'Defense Shield' },
  { key: 'analytics', label: 'Analytics' },
  { key: 'uptime', label: 'Uptime Log' },
  { key: 'ssl', label: 'SSL Certs' },
  { key: 'inventory', label: 'Inventory' },
  { key: 'reports', label: 'Reports' },
]

export default function Nav({ current, onNavigate }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const menuRef = useRef(null)

  useEffect(() => {
    const close = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) setMenuOpen(false)
    }
    document.addEventListener('click', close)
    return () => document.removeEventListener('click', close)
  }, [])

  const menuHasCurrent = MENU_ITEMS.some((item) => item.key === current)

  const goTo = (key) => {
    setMenuOpen(false)
    onNavigate(key)
  }

  return (
    <nav className="nav-bar">
      {PRIMARY_ITEMS.map((item) => (
        <button
          key={item.key}
          className={`nav-item ${current === item.key ? 'active' : ''}`}
          onClick={() => goTo(item.key)}
        >
          {item.label}
        </button>
      ))}
      <div className="nav-menu" ref={menuRef}>
        <button
          className={`nav-item nav-more ${menuHasCurrent ? 'active' : ''}`}
          onClick={() => setMenuOpen(true)}
        >
          More ▾
        </button>
        {menuOpen && (
          <div className="nav-dropdown">
            {MENU_ITEMS.map((item) => (
              <button
                key={item.key}
                className={`nav-dropdown-item ${current === item.key ? 'active' : ''}`}
                onClick={() => goTo(item.key)}
              >
                {item.label}
              </button>
            ))}
          </div>
        )}
      </div>
    </nav>
  )
}
