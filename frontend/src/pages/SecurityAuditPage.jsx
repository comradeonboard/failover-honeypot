import SecurityScanner from '../components/SecurityScanner'
import ScanHistory from '../components/ScanHistory'

export default function SecurityAuditPage({ scans, history, onScan }) {
  return (
    <>
      <SecurityScanner scans={scans} onScan={onScan} />
      <ScanHistory history={history} />
    </>
  )
}
