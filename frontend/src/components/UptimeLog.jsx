export default function UptimeLog({ events }) {
  return (
    <section className="section">
      <h2>Uptime Log</h2>
      <div className="log-container">
        {events.length === 0 ? (
          <p className="empty">No events logged yet</p>
        ) : (
          [...events]
            .reverse()
            .map((e, i) => (
              <div className="log-entry" key={`${e.timestamp}-${i}`}>
                <span className="timestamp">{new Date(e.timestamp).toLocaleTimeString()}</span>
                <span className="event-type">{e.type}</span>
                <span className="details">{e.details}</span>
              </div>
            ))
        )}
      </div>
    </section>
  )
}
