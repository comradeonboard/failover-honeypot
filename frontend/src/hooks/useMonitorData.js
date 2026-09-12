import { useState, useEffect, useCallback } from 'react'

export function useMonitorData() {
  const [status, setStatus] = useState({ primary_up: true, backup_up: false, active: 'primary' })
  const [events, setEvents] = useState([])
  const [alerts, setAlerts] = useState([])
  const [totalAlerts, setTotalAlerts] = useState(0)
  const [services, setServices] = useState([])
  const [stats, setStats] = useState(null)
  const [network, setNetwork] = useState(null)
  const [wsConnected, setWsConnected] = useState(false)
  const [lastUpdated, setLastUpdated] = useState(null)

  const fetchAll = useCallback(async () => {
    try {
      const [statusRes, logRes, alertsRes, servicesRes, statsRes, networkRes] = await Promise.all([
        fetch('/api/status'),
        fetch('/api/uptime-log'),
        fetch('/api/honeypot-alerts'),
        fetch('/api/honeypot/services'),
        fetch('/api/honeypot/stats'),
        fetch('/api/network/devices'),
      ])
      const statusData = await statusRes.json()
      const logData = await logRes.json()
      const alertsData = await alertsRes.json()
      const servicesData = await servicesRes.json()
      const statsData = await statsRes.json()
      const networkData = await networkRes.json()

      setStatus(statusData)
      setEvents(logData.events || [])
      setAlerts(alertsData.alerts || [])
      setTotalAlerts(alertsData.total_alerts || 0)
      setServices(servicesData.services || [])
      setStats(statsData)
      setNetwork(networkData)
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
      await fetch(`/api/honeypot/toggle/${name}`, { method: 'POST' })
      fetchAll()
    } catch (err) {
      console.error('Toggle error:', err)
    }
  }, [fetchAll])

  const clearAlerts = useCallback(async () => {
    try {
      await fetch('/api/honeypot/clear', { method: 'POST' })
      fetchAll()
    } catch (err) {
      console.error('Clear error:', err)
    }
  }, [fetchAll])

  const triggerScan = useCallback(async () => {
    try {
      await fetch('/api/network/scan', { method: 'POST' })
      fetchAll()
    } catch (err) {
      console.error('Scan error:', err)
    }
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
    status, events, alerts, totalAlerts, services, stats, network,
    wsConnected, lastUpdated, toggleService, clearAlerts, triggerScan,
  }
}
