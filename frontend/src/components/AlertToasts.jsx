export default function AlertToasts({ toasts, onDismiss }) {
  if (!toasts || toasts.length === 0) return null
  return (
    <div className="toast-stack">
      {toasts.map((t) => (
        <div
          className={`alert-toast ${t.level}`}
          key={t.id}
          onClick={() => onDismiss(t.id)}
          title="Click to dismiss"
        >
          <div className="toast-title">{t.title}</div>
          <div className="toast-body">{t.body}</div>
        </div>
      ))}
    </div>
  )
}
