import { useState, useEffect } from 'react'
import Login from './components/Login'
import Dashboard from './Dashboard'
import { sfx } from './lib/sfx'

const TOKEN_KEY = 'fhm_token'

export default function App() {
  const [authed, setAuthed] = useState(() => !!localStorage.getItem(TOKEN_KEY))

  useEffect(() => {
    const onLogout = () => setAuthed(false)
    window.addEventListener('fhm:logout', onLogout)
    return () => window.removeEventListener('fhm:logout', onLogout)
  }, [])

  const handleLogout = () => {
    sfx.logout()
    const token = localStorage.getItem(TOKEN_KEY)
    localStorage.removeItem(TOKEN_KEY)
    if (token) {
      fetch('/api/auth/logout', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
      }).catch(() => {})
    }
    setAuthed(false)
  }

  if (!authed) return <Login onSuccess={() => setAuthed(true)} />
  return <Dashboard onLogout={handleLogout} />
}
