import HoneypotServices from '../components/HoneypotServices'
import HoneypotAlerts from '../components/HoneypotAlerts'
import AiExplanation from '../components/AiExplanation'

export default function HoneypotPage({ services, alerts, totalAlerts, onToggle, onClear }) {
  return (
    <>
      <HoneypotServices services={services} onToggle={onToggle} />
      <HoneypotAlerts alerts={alerts} totalAlerts={totalAlerts} onClear={onClear} />
      <section className="section">
        <div className="section-header-row">
          <h2>AI Attack Analysis</h2>
        </div>
        <p className="section-desc">
          Claude reviews the captured honeypot activity and explains what the attackers are after.
        </p>
        <AiExplanation endpoint="/api/ai/honeypot" buttonLabel="Analyze with Claude" />
      </section>
    </>
  )
}
