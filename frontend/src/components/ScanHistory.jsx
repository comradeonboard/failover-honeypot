import { useState } from 'react'

const downloadCsv = async (params, filename) => {
  const token = localStorage.getItem('fhm_token')
  const res = await fetch(`/api/security/export${params}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) throw new Error('Export failed')
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export default function ScanHistory({ history }) {
  const [openId, setOpenId] = useState(null)
  const [exporting, setExporting] = useState(null)
  const list = history || []

  const exportOne = async (e, h) => {
    e.stopPropagation()
    setExporting(h.id)
    try {
      await downloadCsv(`?scan_id=${h.id}`, `audit-${h.id}.csv`)
    } finally {
      setExporting(null)
    }
  }

  const exportAll = async () => {
    setExporting('all')
    try {
      await downloadCsv('', `audits-all-${new Date().toISOString().slice(0, 10)}.csv`)
    } finally {
      setExporting(null)
    }
  }

  return (
    <section className="section">
      <div className="history-head">
        <div>
          <h2>Audit History</h2>
          <p className="section-desc">Every audit you have run, kept across restarts.</p>
        </div>
        {list.length > 0 && (
          <button className="export-btn" onClick={exportAll} disabled={exporting === 'all'}>
            {exporting === 'all' ? 'Exporting' : 'Export All (CSV)'}
          </button>
        )}
      </div>
      {list.length === 0 ? (
        <p className="empty">No audits recorded yet</p>
      ) : (
        <div className="history-list">
          {list.map((h) => (
            <div
              className={`history-row ${openId === h.id ? 'open' : ''}`}
              key={h.id}
              onClick={() => setOpenId(openId === h.id ? null : h.id)}
            >
              <span className="timestamp">{new Date(h.scanned_at).toLocaleString()}</span>
              <span className="history-target">{h.target}</span>
              {h.status === 'complete' ? (
                <>
                  <span className={`grade-badge ${String(h.grade).toLowerCase()}`}>{h.grade}</span>
                  <span className="history-score">{h.score}/100</span>
                </>
              ) : (
                <span className="audit-status failed">Unreachable</span>
              )}
              <span className="history-count">{h.findings_count} finding{h.findings_count === 1 ? '' : 's'}</span>
              <button
                className="export-btn small"
                onClick={(e) => exportOne(e, h)}
                disabled={exporting === h.id}
                title="Download this audit as a spreadsheet"
              >
                {exporting === h.id ? '…' : 'CSV'}
              </button>
              {openId === h.id && h.findings?.length > 0 && (
                <div className="history-findings">
                  {h.findings.map((f, i) => (
                    <div className="finding" key={i}>
                      <span className={`sev-chip ${f.severity}`}>{f.severity}</span>
                      <div className="finding-body">
                        <p className="finding-title">{f.title}</p>
                        <p className="finding-detail">{f.detail}</p>
                        <p className="finding-fix">Fix: {f.fix}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
