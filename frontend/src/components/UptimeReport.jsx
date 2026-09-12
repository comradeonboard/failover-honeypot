import { useState, useEffect } from 'react'
import { apiGet } from '../lib/api'

const RANGES = [
  { days: 7, label: '7 days' },
  { days: 30, label: '30 days' },
  { days: 90, label: '90 days' },
]

const pct = (v) => (v == null ? '--' : `${v.toFixed(v % 1 === 0 ? 0 : 1)}%`)

export default function UptimeReport() {
  const [days, setDays] = useState(30)
  const [report, setReport] = useState(null)
  const [error, setError] = useState('')

  useEffect(() => {
    apiGet(`/api/uptime/report?days=${days}`)
      .then((r) => {
        setReport(r)
        setError('')
      })
      .catch((e) => setError(e.message))
  }, [days])

  const systemCard = (name, s) => (
    <div className="stat-card" key={name}>
      <p className="card-label">{name}</p>
      <p className="stat-value">{pct(s?.uptime_pct)}</p>
      <p className="card-sub">{s ? `${s.incidents} incident${s.incidents === 1 ? '' : 's'}` : 'no data yet'}</p>
    </div>
  )

  return (
    <section className="section">
      <div className="history-head">
        <div>
          <h2>Uptime Report</h2>
          <p className="section-desc">
            Availability sampled once a minute.
            {report?.tracked_since
              ? ` Tracked since ${new Date(report.tracked_since).toLocaleString()}.`
              : ' Tracking starts now — percentages build up as samples accumulate.'}
          </p>
        </div>
        <div className="range-tabs">
          {RANGES.map((r) => (
            <button
              key={r.days}
              className={`range-tab ${days === r.days ? 'active' : ''}`}
              onClick={() => setDays(r.days)}
            >
              {r.label}
            </button>
          ))}
        </div>
      </div>
      {error && <div className="login-error">{error}</div>}
      {report && (
        <>
          <div className="stat-grid">
            {systemCard('Primary Link', report.primary)}
            {systemCard('Backup Link', report.backup)}
            <div className="stat-card">
              <p className="card-label">Samples</p>
              <p className="stat-value">{report.samples}</p>
              <p className="card-sub">one per minute</p>
            </div>
          </div>
          {report.daily.length === 0 ? (
            <p className="empty">Not enough data yet — the first daily bars appear within minutes.</p>
          ) : (
            <div className="report-chart">
              <div className="chart-bars">
                {report.daily.map((d) => (
                  <div className="chart-day" key={d.date}>
                    <div className="chart-stack">
                      <div
                        className="chart-bar primary"
                        style={{ height: `${Math.max(2, d.primary_pct ?? 0)}%` }}
                        title={`Primary ${pct(d.primary_pct)}`}
                      />
                      <div
                        className="chart-bar backup"
                        style={{ height: `${Math.max(2, d.backup_pct ?? 0)}%` }}
                        title={`Backup ${pct(d.backup_pct)}`}
                      />
                    </div>
                    <span className="chart-date">{d.date.slice(5)}</span>
                  </div>
                ))}
              </div>
              <div className="chart-legend">
                <span><span className="legend-dot primary" /> Primary</span>
                <span><span className="legend-dot backup" /> Backup</span>
              </div>
            </div>
          )}
        </>
      )}
    </section>
  )
}
