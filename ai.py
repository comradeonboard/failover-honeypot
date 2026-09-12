"""Anthropic Claude integration for the FHM console.

Three AI features:
- explain_audit: plain-English verdict + fix advice for a web security audit
- honeypot_analysis: what the captured attacker activity means
- assistant_reply: chat answers grounded in live console data
"""
import json
import logging
import os
import urllib.request
import urllib.error

logger = logging.getLogger("fhm.ai")

API_URL = "https://api.anthropic.com/v1/messages"


class AiError(Exception):
    """Carries an HTTP status for the API layer."""

    def __init__(self, message, status=502):
        super().__init__(message)
        self.status = status


def claude_call(system, messages, max_tokens=1600):
    key = os.environ.get("ANTHROPIC_API_KEY", "").strip()
    if not key:
        raise AiError(
            "Claude is not configured — add the ANTHROPIC_API_KEY secret in Settings.",
            status=503,
        )
    payload = {
        "model": os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-4-5").strip() or "claude-sonnet-4-5",
        "max_tokens": max_tokens,
        "system": system,
        "messages": messages,
    }
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        logger.error(f"Claude API error {e.code}: {detail}")
        if e.code == 401:
            raise AiError("Claude rejected the API key — check the ANTHROPIC_API_KEY secret.", status=503)
        raise AiError(f"Claude API error ({e.code}) — try again shortly.", status=502)
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        logger.error(f"Claude API unreachable: {e}")
        raise AiError("Could not reach the Claude API — check network connectivity.", status=502)
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


AUDIT_SYSTEM = (
    "You are a security analyst explaining the results of a web security audit "
    "to the operator of a monitoring console. Write in clear plain English and be "
    "direct and practical. Structure: (1) one-sentence overall verdict, "
    "(2) the biggest risks and what they could lead to, briefly, "
    "(3) prioritized fix advice. Short paragraphs or bullets, no markdown "
    "headings, max ~200 words."
)


def explain_audit(entry):
    prompt = json.dumps({
        "target": entry.get("target"),
        "grade": entry.get("grade"),
        "score": entry.get("score"),
        "findings": entry.get("findings", []),
    }, default=str)[:16000]
    return claude_call(
        AUDIT_SYSTEM,
        [{"role": "user", "content": "Explain these audit results:\n" + prompt}],
    )


HONEYPOT_SYSTEM = (
    "You are a honeypot security analyst. You receive captured attack alerts "
    "(attacker IPs, services probed, severity, payloads) from a tarpit-style "
    "honeypot. Summarize in plain English: what the attackers appear to be doing "
    "and looking for, how coordinated or automated the activity looks, what it "
    "suggests about exposure, and 2-3 practical recommendations. Concise, short "
    "paragraphs or bullets, max ~200 words, no headings."
)


def honeypot_analysis(alerts, stats, banned_ips):
    sample = [
        {k: a.get(k) for k in ("timestamp", "type", "source_ip", "service", "severity", "data")}
        for a in list(alerts)[-60:]
    ]
    prompt = json.dumps({
        "stats": stats,
        "recent_alerts": sample,
        "currently_banned": banned_ips,
    }, default=str)[:16000]
    return claude_call(
        HONEYPOT_SYSTEM,
        [{"role": "user", "content": "Analyze this honeypot activity:\n" + prompt}],
    )


ASSISTANT_SYSTEM = (
    "You are the AI assistant of a network security monitoring console "
    "(failover & honeypot monitor). Answer the operator's questions using the "
    "live console data provided in the user turn. Be concise and practical. "
    "If the data does not contain the answer, say so plainly and answer from "
    "general security knowledge, noting it is general advice. "
    "No markdown headings, max ~250 words."
)


def assistant_reply(history, context_json):
    messages = [dict(m) for m in history]
    if messages and messages[-1]["role"] == "user":
        messages[-1] = {
            "role": "user",
            "content": (
                f"Console data (JSON):\n{context_json}\n\n"
                f"Question: {messages[-1]['content']}"
            ),
        }
    return claude_call(ASSISTANT_SYSTEM, messages, max_tokens=900)
