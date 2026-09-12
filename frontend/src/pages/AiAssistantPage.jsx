import { useEffect, useRef, useState } from 'react'
import { apiPost } from '../lib/api'

export default function AiAssistantPage() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [busy, setBusy] = useState(false)
  const endRef = useRef(null)

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, busy])

  const send = async (e) => {
    e.preventDefault()
    const q = input.trim()
    if (!q || busy) return
    setInput('')
    const next = [...messages, { role: 'user', content: q }]
    setMessages(next)
    setBusy(true)
    try {
      const res = await apiPost('/api/ai/assistant', { messages: next.slice(-12) })
      setMessages((m) => [...m, { role: 'assistant', content: res.reply }])
    } catch (err) {
      setMessages((m) => [...m, { role: 'assistant', content: `Error: ${err.message}` }])
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="section assistant-section">
      <h2>AI Assistant</h2>
      <p className="section-desc">
        Ask about your honeypot attacks, banned IPs, network devices, uptime and audits.
        Answers use your live console data. Powered by Claude.
      </p>
      <div className="assistant-chat">
        {messages.length === 0 && (
          <p className="empty">Ask anything about your console data — e.g. "which attacker IP is the most active?"</p>
        )}
        {messages.map((m, i) => (
          <div key={i} className={`assistant-msg ${m.role}`}>
            {m.content}
          </div>
        ))}
        {busy && <div className="assistant-msg assistant thinking">Thinking…</div>}
        <div ref={endRef} />
      </div>
      <form className="assistant-input-row" onSubmit={send}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Type your question…"
        />
        <button type="submit" className="ai-btn" disabled={busy || !input.trim()}>
          {busy ? 'Thinking…' : 'Send'}
        </button>
      </form>
    </section>
  )
}
