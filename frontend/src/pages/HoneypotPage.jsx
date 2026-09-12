import HoneypotServices from '../components/HoneypotServices'
import HoneypotAlerts from '../components/HoneypotAlerts'

export default function HoneypotPage({ services, alerts, totalAlerts, onToggle, onClear }) {
  return (
    <>
      <HoneypotServices services={services} onToggle={onToggle} />
      <HoneypotAlerts alerts={alerts} totalAlerts={totalAlerts} onClear={onClear} />
    </>
  )
}
