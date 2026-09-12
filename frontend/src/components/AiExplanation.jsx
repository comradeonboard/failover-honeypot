import { useState } from 'react'
import { apiPost } from '../lib/api'

export default function AiExplanation({ endpoint, buttonLabel = 'Explain with AI' }) {
  const [text, setText] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  const run = async (e) => {
    e.stopPropagation()
    if (loading) return
    setLoading(true)
    setError(null)
    try {
      const res = await apiPost(endpoint)
      setText(res.explanation || res.reply || 'No analysis returned.')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="ai-explain">
      <button className="ai-btn" onClick={run} disabled={loading}>
        {loading ? 'Analyzing…' : buttonLabel}
      </button>
      {error && <p className="ai-error">{error}</p>}
      {text && <div className="ai-output">{text}</div>}
    </div>
  )
}
