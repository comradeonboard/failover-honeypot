import { useState, useEffect, useCallback } from 'react'

export function useMonitorData() {
  const [status, setStatus] = useState({ primary_up: true, backup_up: false, active: 'primary' })
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [totalAlerts, setTotalAlerts] = useState(0)
  const [wsConnected, setWsConnected] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const fetchAll = useCallback(async () => {
    try {
      const [statusRes, logRes, alertsRes] = await Promise.all([
        fetch('/api/status'),
        fetch('/api/uptime-log'),
        fetch('/api/honeypot-alerts'),
      ])
      const statusData = await statusRes.json()
      const logData = await logRes.json()
      const alertsData = await alertsRes.json()

      setStatus(statusData)
      setEvents(logData.events || [])
      setAlerts(alertsData.alerts || [])
      setTotalAlerts(alertsData.total_alerts || 0)
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

  useEffect(() => {
    let ws = null
    let reconnectTimeout = null
    let isMounted = true

    const connect = () => {
      if (!isMounted) return
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      ws = new WebSocket(`${protocol}//${window.location.host}/ws`)

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

  return { status, events, alerts, totalAlerts, wsConnected, lastUpdated }
}
