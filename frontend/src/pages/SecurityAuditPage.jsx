import SecurityScanner from '../components/SecurityScanner'

export default function SecurityAuditPage({ scans, onScan }) {
  return <SecurityScanner scans={scans} onScan={onScan} />
}
