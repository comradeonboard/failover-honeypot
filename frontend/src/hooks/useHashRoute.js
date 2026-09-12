import { useState, useEffect } from 'react'

/**
 * Minimal hash-based router. Returns the current route key
 * (the part after '#/', e.g. '#/network' → 'network') and a
 * navigate function. Defaults to 'overview' when no hash is set.
 */
export function useHashRoute() {
  const parse = () => {
    const hash = window.location.hash.replace(/^#\/?/, '')
    return hash || 'overview'
  }

  const [route, setRoute] = useState(parse)

  useEffect(() => {
    const onHashChange = () => setRoute(parse())
    window.addEventListener('hashchange', onHashChange)
    return () => window.removeEventListener('hashchange', onHashChange)
  }, [])

  const navigate = (key) => {
    window.location.hash = `/${key}`
  }

  return [route, navigate]
}
