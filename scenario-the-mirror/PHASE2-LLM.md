# Phase 2: Adding an LLM to the Decision Layer

## What Changes (and What Doesn't)

In Phase 1, the agent's decision logic is a series of `if` statements:

```python
# Phase 1: rule-based
if alert_category in ["attempted-recon", "network-scan"]:
    if user_agent matches known_tool:
        execute("redirect-to-honeypot")
```

In Phase 2, you replace that decision logic with an LLM — but **everything else stays the same**. The action pool, the audit log, the OSINT modules, the honeypot, the systemd service, the permissions model. The LLM doesn't get new capabilities. It gets the same menu of pre-approved actions the rule-based agent had.

```python
# Phase 2: LLM-based
response = llm.evaluate(telemetry_event, action_pool)
if response.action in pool and pool.can_execute(response.action):
    execute(response.action)
```

The guardrails don't change. The intelligence does.

## What the LLM Actually Sees

You'd send the LLM a structured prompt with three things:

1. **The telemetry event** — the raw Suricata alert, HTTP headers, user-agent, source IP
2. **The action pool** — the list of actions it's allowed to take, with constraints
3. **Recent context** — what other events have come from this IP, what actions have already been taken

```
You are a defensive security agent. Analyze this telemetry event and decide
what action to take. You may ONLY choose from the action pool below. If no
action is appropriate, respond with "no_action".

## Telemetry Event
{
  "event_type": "alert",
  "src_ip": "198.51.100.23",
  "alert": {"signature": "ET SCAN Nmap Scripting Engine", "severity": 2},
  "http": {"http_user_agent": "Nuclei - Open-source project"}
}

## Action Pool (pre-approved)
- redirect-to-honeypot (Tier 1): Redirect traffic to honeypot
- run-osint (Tier 1): Run passive OSINT on source IP
- temp-block-ip (Tier 1): Temporary IP block (1h expiry)
- collect-honeypot-evidence (Tier 1): Collect honeypot interaction logs
- block-ip-range (Tier 2): Block CIDR range (requires confidence > 0.85)
- no_action: Do nothing

## Recent Context
- No prior events from this IP
- 3 other IPs triggered recon alerts in the last hour

## Instructions
Respond with JSON: {"action": "...", "reasoning": "...", "confidence": 0.0-1.0}
```

The LLM responds:

```json
{
  "action": "redirect-to-honeypot",
  "reasoning": "Source IP triggered an IDS alert for Nmap scanning and is using the
    Nuclei vulnerability scanner (identified via user-agent). The combination of
    port scanning and active vulnerability probing from the same source indicates
    deliberate reconnaissance, not accidental traffic. Redirecting to honeypot to
    collect TTPs while running OSINT.",
  "confidence": 0.95
}
```

The agent then validates that `redirect-to-honeypot` is in the pool, checks constraints, executes, and logs. The LLM's reasoning goes straight into the audit log — it becomes part of the post-mortem report the team reads in the morning.

## What Value the LLM Adds

### 1. Novel Pattern Recognition

The rule-based agent only catches patterns you've written rules for. If an attacker uses a custom tool with a user-agent you've never seen, the rule-based agent misses it.

The LLM can reason about *why* something is suspicious even without an exact signature match:

> "The user-agent `Mozilla/5.0 security-audit-tool/0.1` is not in the known signatures database, but it identifies itself as a security audit tool. Combined with the high rate of 404 responses from this IP (directory enumeration pattern), this is likely an offensive scanning tool with a custom user-agent."

You'd never write a rule for a tool you haven't heard of. The LLM can reason about it anyway.

### 2. Correlating Weak Signals

Individual signals that are too weak to act on alone can be meaningful together. The rule-based agent either fires or doesn't — it can't weigh combinations.

The LLM can reason across signals:

> "Individually, none of these signals are conclusive: python-requests user-agent (low confidence), 3am request time (unusual but not actionable), requests to /api/v1/users endpoint (legitimate endpoint). However, the combination — an automated HTTP client making API calls to user-enumeration endpoints at 3am — is consistent with pre-attack reconnaissance. Recommending redirect-to-honeypot."

### 3. Natural Language Reasoning in the Audit Trail

The rule-based agent logs `"reason": "matched recon category"`. Useful, but terse.

The LLM writes human-readable explanations:

> "This source was redirected to the honeypot because it exhibited a classic attack progression: port scanning (03:14), followed by vulnerability scanning with Nuclei (03:18), followed by targeted SQL injection attempts with sqlmap (03:22). The 4-minute gaps between tool switches suggest a human operator working through a methodology, not automated spray-and-pray. The OSINT dossier should reveal whether this is a VPS (likely attacker infrastructure) or a compromised legitimate host."

When the security team reads the post-mortem at 8am, they get analysis, not just data.

### 4. Adaptive Confidence Scoring

The rule-based agent assigns static confidence scores — `Nuclei` is always 0.95, `python-requests` is always 0.5.

The LLM adjusts confidence based on context:

- `python-requests` hitting `/docs` at 2pm → low confidence (probably a developer)
- `python-requests` hitting `/admin/api/users` at 3am from a VPN IP → high confidence
- `python-requests` hitting `/admin/api/users` at 3am from a VPN IP, and two other VPN IPs hit the same endpoint in the last hour → very high confidence, recommend Tier 2 escalation

Same user-agent, wildly different threat levels. The LLM sees the full picture.

### 5. Action Pool Feedback

After an incident, the LLM can analyze what happened and suggest improvements to the action pool:

> "During this incident, the agent detected DNS tunneling via entropy analysis (playbook 09) but could not act on it because `sinkhole-domain` is Tier 2 and the on-call engineer didn't respond for 40 minutes. Given that the entropy score was 4.8 (well above the 3.5 threshold) and 3 internal hosts were actively querying the domain, consider promoting `sinkhole-domain` to Tier 1 for cases where entropy exceeds 4.5 and internal hosts are actively resolving."

The rule-based agent can't reason about its own limitations. The LLM can.

## What the LLM Does NOT Get

The LLM is powerful, but it's constrained:

- **No actions outside the pool.** If the pool has 6 actions, the LLM picks from 6 actions. It can't invent a 7th.
- **No direct system access.** The LLM produces a JSON response. The agent code validates it, checks the pool, and executes. The LLM never runs a command.
- **No pool modification.** The LLM can *suggest* pool changes in the post-mortem. The security team decides whether to apply them.
- **No memory between restarts.** Each event is evaluated independently (with recent context window). The LLM doesn't accumulate state outside the audit log.
- **Same permissions as Phase 1.** The systemd unit, capabilities, and filesystem restrictions are identical. Swapping in an LLM doesn't change the blast radius.

The architecture is: **the LLM decides, the pool constrains, the code executes, the audit log records.**

## Implementation Sketch

```python
import anthropic

client = anthropic.Anthropic()

def llm_decide(event, pool, recent_context):
    """Ask the LLM to evaluate a telemetry event and choose an action."""
    prompt = build_prompt(event, pool, recent_context)

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )

    decision = parse_json_response(response.content[0].text)

    # The LLM's choice is a suggestion — validate it against the pool
    action = decision.get("action", "no_action")
    if action == "no_action":
        return None

    can_execute, reason = pool.can_execute(action)
    if not can_execute:
        audit.record(action=action, result="skipped",
                     reason=f"Pool rejected: {reason}",
                     llm_reasoning=decision.get("reasoning"))
        return None

    return {
        "action": action,
        "reasoning": decision.get("reasoning", ""),
        "confidence": decision.get("confidence", 0.0),
    }
```

You'd use a fast, cost-effective model (Claude Sonnet) for the per-event decisions — the agent processes events continuously, so you need low latency and reasonable cost. For the post-mortem synthesis and action pool feedback, you could use a more capable model (Claude Opus) since that runs once per incident, not once per event.

## When to Move to Phase 2

Phase 1 (rule-based) is the right starting point. Move to Phase 2 when:

- You're seeing attacks that your rules don't catch
- Your post-mortem reports need better explanations for stakeholders
- You want the agent to correlate weak signals across multiple events
- Your action pool is stable and well-tested (the LLM shouldn't be the first thing choosing actions — get the pool right with rules first)

Phase 1 and Phase 2 can also coexist: use rules for high-confidence, well-known patterns (Nmap scan → redirect, always), and the LLM for ambiguous situations where judgment is needed.
