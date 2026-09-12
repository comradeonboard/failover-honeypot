import { useState, useEffect, useCallback } from 'react'

const TOKEN_KEY = 'fhm_token'

const authHeaders = () => {
  const token = localStorage.getItem(TOKEN_KEY)
  return token ? { Authorization: `Bearer ${token}` } : {}
}

const handleAuthFailure = () => {
  localStorage.removeItem(TOKEN_KEY)
  window.dispatchEvent(new Event('fhm:logout'))
}

export function useMonitorData() {
  const [status, setStatus] = useState({ primary_up: true, backup_up: false, active: 'primary' })
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [totalAlerts, setTotalAlerts] = useState(0)
  const [services, setServices] = useState([])
  const [stats, setStats] = useState(null)
  const [network, setNetwork] = useState(null)
  const [securityScans, setSecurityScans] = useState([])
  const [wsConnected, setWsConnected] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const fetchAll = useCallback(async () => {
    try {
      const responses = await Promise.all([
        fetch('/api/status', { headers: authHeaders() }),
        fetch('/api/uptime-log', { headers: authHeaders() }),
        fetch('/api/honeypot-alerts', { headers: authHeaders() }),
        fetch('/api/honeypot/services', { headers: authHeaders() }),
        fetch('/api/honeypot/stats', { headers: authHeaders() }),
        fetch('/api/network/devices', { headers: authHeaders() }),
        fetch('/api/security/scans', { headers: authHeaders() }),
      ])
      if (responses.some((r) => r.status === 401)) {
        handleAuthFailure()
        return
      }
      const [statusData, logData, alertsData, servicesData, statsData, networkData, securityData] =
        await Promise.all(responses.map((r) => r.json()))

      setStatus(statusData)
      setEvents(logData.events || [])
      setAlerts(alertsData.alerts || [])
      setTotalAlerts(alertsData.total_alerts || 0)
      setServices(servicesData.services || [])
      setStats(statsData)
      setNetwork(networkData)
      setSecurityScans(securityData.scans || [])
      setLastUpdated(new Date())
    } catch (err) {
      console.error('Fetch error:', err)
    }
  }, [])

  useEffect(() => {
    fetchAll()
    const interval = setInterval(fetchAll, 5000)
    return () => clearInterval(interval)
  }, [fetchAll])

  const toggleService = useCallback(async (name) => {
    try {
      await fetch(`/api/honeypot/toggle/${name}`, { method: 'POST', headers: authHeaders() })
      fetchAll()
    } catch (err) {
      console.error('Toggle error:', err)
    }
  }, [fetchAll])

  const clearAlerts = useCallback(async () => {
    try {
      await fetch('/api/honeypot/clear', { method: 'POST', headers: authHeaders() })
      fetchAll()
    } catch (err) {
      console.error('Clear error:', err)
    }
  }, [fetchAll])

  const triggerScan = useCallback(async () => {
    try {
      await fetch('/api/network/scan', { method: 'POST', headers: authHeaders() })
      fetchAll()
    } catch (err) {
      console.error('Scan error:', err)
    }
  }, [fetchAll])

  const scanWebsite = useCallback(async (target) => {
    try {
      await fetch('/api/security/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders() },
        body: JSON.stringify({ target }),
      })
      fetchAll()
    } catch (err) {
      console.error('Security scan error:', err)
    }
  }, [fetchAll])

  useEffect(() => {
    let ws = null
    let reconnectTimeout = null
    let isMounted = true

    const connect = () => {
      if (!isMounted) return
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const token = encodeURIComponent(localStorage.getItem(TOKEN_KEY) || '')
      ws = new WebSocket(`${protocol}//${window.location.host}/ws?token=${token}`)

      ws.onopen = () => {
        if (isMounted) setWsConnected(true)
      }

      ws.onmessage = (e) => {
        if (!isMounted) return
        try {
          const data = JSON.parse(e.data)
          if (data.status) setStatus(data.status)
          if (data.uptime_log) setEvents(data.uptime_log)
          if (data.honeypot_alerts) setAlerts(data.honeypot_alerts)
          if (data.total_alerts !== undefined) setTotalAlerts(data.total_alerts)
          if (data.honeypot_services) setServices(data.honeypot_services)
          if (data.attack_stats) setStats(data.attack_stats)
          if (data.network) setNetwork(data.network)
          setLastUpdated(new Date())
        } catch (err) {
          console.error('WS parse error:', err)
        }
      }

      ws.onclose = () => {
        if (!isMounted) return
        setWsConnected(false)
        reconnectTimeout = setTimeout(connect, 3000)
      }
    }

    connect()

    return () => {
      isMounted = false
      clearTimeout(reconnectTimeout)
      if (ws) {
        ws.onclose = null
        ws.close()
      }
    }
  }, [])

  return {
    status, events, alerts, totalAlerts, services, stats, network, securityScans,
    wsConnected, lastUpdated, toggleService, clearAlerts, triggerScan, scanWebsite,
  }
}
