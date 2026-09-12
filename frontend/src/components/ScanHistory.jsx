import { useState } from 'react'

export default function ScanHistory({ history }) {
  const [openId, setOpenId] = useState(null)
  const list = history || []

  return (
    <section className="section">
      <h2>Audit History</h2>
      <p className="section-desc">Every audit you have run, kept across restarts.</p>
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
