import { useState } from 'react'

export default function SecurityScanner({ scans, onScan }) {
  const [target, setTarget] = useState('')
  const scanList = scans || []
  const scanning = scanList.some((s) => s.status === 'scanning')

  const handleSubmit = (e) => {
    e.preventDefault()
    if (!target.trim() || scanning) return
    onScan(target.trim())
  }

  return (
    <section className="section">
      <div className="section-header-row">
        <h2>Web Weak-Point Audit</h2>
        <span className="audit-note">Authorized bug-bounty targets only</span>
      </div>
      <form className="audit-form" onSubmit={handleSubmit}>
        <input
          className="audit-input"
          type="text"
          placeholder="target site, e.g. https://example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <button className="scan-btn" type="submit" disabled={scanning || !target.trim()}>
          {scanning ? 'Auditing' : 'Audit'}
        </button>
      </form>
      <div className="audit-results">
        {scanList.length === 0 && !scanning && (
          <p className="empty">No audits yet — enter a target you are authorized to test</p>
        )}
        {scanList.map((s) => (
          <div className="audit-result" key={`${s.target}-${s.scanned_at}`}>
            <div className="audit-result-header">
              <span className="audit-target">{s.target}</span>
              {s.status === 'scanning' && (
                <span className="audit-status scanning">Auditing</span>
              )}
              {s.status === 'error' && (
                <span className="audit-status failed">Unreachable</span>
              )}
              {s.status === 'complete' && (
                <>
                  <span className={`grade-badge ${s.grade.toLowerCase()}`}>{s.grade}</span>
                  <span className="audit-score">{s.score}/100</span>
                </>
              )}
              <span className="audit-date">{new Date(s.scanned_at).toLocaleTimeString()}</span>
            </div>
            {s.status === 'complete' && (
              <div className="findings">
                {s.findings.length === 0 ? (
                  <p className="empty">No weak points found</p>
                ) : (
                  s.findings.map((f, i) => (
                    <div className="finding" key={i}>
                      <span className={`sev-chip ${f.severity}`}>{f.severity}</span>
                      <div className="finding-body">
                        <p className="finding-title">{f.title}</p>
                        <p className="finding-detail">{f.detail}</p>
                        <p className="finding-fix">Fix: {f.fix}</p>
                      </div>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        ))}
      </div>
    </section>
  )
}
