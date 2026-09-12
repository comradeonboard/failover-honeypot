import StatusSection from '../components/StatusSection'
import HostsPanel from '../components/HostsPanel'

export default function OverviewPage({ status, hosts }) {
  return (
    <>
      <StatusSection status={status} />
      <HostsPanel hosts={hosts} />
    </>
  )
}
