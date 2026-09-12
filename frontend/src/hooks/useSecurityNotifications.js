import { useCallback, useEffect, useRef, useState } from 'react'

// Which events raise a notification
const NOTIFY_SEVERITIES = new Set(['high'])      // honeypot alert severities
const NOTIFY_EVENT_TYPES = new Set(['BAN'])      // defense event types

export function useSecurityNotifications(alerts, defense) {
  const supported = typeof Notification !== 'undefined'
  const [permission, setPermission] = useState(supported ? Notification.permission : 'denied')
  const [toasts, setToasts] = useState([])
  const seenAlerts = useRef(null)
  const seenEvents = useRef(null)

  const requestPermission = useCallback(async () => {
    if (!supported) return
    try {
      const result = await Notification.requestPermission()
      setPermission(result)
    } catch (err) {
      console.error('Notification permission error:', err)
    }
  }, [supported])

  const dismissToast = useCallback((id) => {
    setToasts((t) => t.filter((x) => x.id !== id))
  }, [])

  const notify = useCallback((title, body, level) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    setToasts((t) => [...t.slice(-3), { id, title, body, level }])
    setTimeout(() => {
      setToasts((t) => t.filter((x) => x.id !== id))
    }, 9000)
    if (supported && Notification.permission === 'granted') {
      try {
        new Notification(title, { body })
      } catch (err) {
        /* native notifications unavailable in this context */
      }
    }
  }, [supported])

  // Honeypot alerts → intrusion attempt notifications
  useEffect(() => {
    if (!alerts || alerts.length === 0) return
    const keys = alerts.map((a) => `${a.timestamp}|${a.source_ip}|${a.type}`)
    if (seenAlerts.current === null) {
      seenAlerts.current = new Set(keys) // baseline — don't notify for history
      return
    }
    alerts.forEach((a, i) => {
      const key = keys[i]
      if (seenAlerts.current.has(key)) return
      seenAlerts.current.add(key)
      if (NOTIFY_SEVERITIES.has(a.severity)) {
        notify(
          'INTRUSION ATTEMPT DETECTED',
          `${String(a.type || '').replace(/_/g, ' ')} — ${a.source_ip} (${a.service})${a.data ? `: ${a.data}` : ''}`,
          'critical'
        )
      }
    })
  }, [alerts, notify])

  // Defense events → attacker-blocked notifications
  useEffect(() => {
    if (!defense || !defense.events) return
    const events = defense.events
    const keys = events.map((e) => `${e.timestamp}|${e.type}|${e.message}`)
    if (seenEvents.current === null) {
      seenEvents.current = new Set(keys) // baseline
      return
    }
    events.forEach((e, i) => {
      const key = keys[i]
      if (seenEvents.current.has(key)) return
      seenEvents.current.add(key)
      if (NOTIFY_EVENT_TYPES.has(e.type)) {
        notify('ATTACKER BLOCKED', e.message, 'blocked')
      }
    })
  }, [defense, notify])

  return { permission, requestPermission, toasts, dismissToast }
}
