"""
Prompt templates for LLM-based security event evaluation.
"""
import json
from typing import Dict, Any, Optional, List


def build_evaluation_prompt(
    event: Dict[str, Any],
    action_pool: List[Dict[str, Any]],
    recent_context: Optional[List[Dict[str, Any]]] = None
) -> str:
    """
    Build a structured prompt for LLM evaluation of a security event.

    Args:
        event: Suricata EVE event or similar telemetry
        action_pool: List of available actions
        recent_context: Recent events from same source IP (optional)

    Returns:
        Formatted prompt string
    """
    # Format action pool for prompt
    actions_text = _format_action_pool(action_pool)

    # Format recent context if available
    context_text = _format_recent_context(recent_context) if recent_context else "No prior events from this source IP."

    # Build the prompt
    prompt = f"""You are a defensive cybersecurity agent analyzing network telemetry to detect and respond to attacks.

## Your Task

Analyze the security event below and decide what action to take. You may ONLY choose from the pre-approved action pool. If no action is appropriate, respond with "no_action".

## Telemetry Event

```json
{json.dumps(event, indent=2)}
```

## Action Pool (Pre-Approved Actions)

{actions_text}

## Recent Context

{context_text}

## Analysis Guidelines

1. **Novel Pattern Recognition**: Even if a tool/user-agent isn't in your database, reason about whether the behavior indicates reconnaissance or attack activity.

2. **Weak Signal Correlation**: Consider combinations of signals that individually seem benign but together form a suspicious pattern.

3. **Context Matters**: The same user-agent can be legitimate at 2pm or malicious at 3am. Consider timing, endpoints accessed, response patterns, etc.

4. **Confidence Scoring**:
   - 0.9-1.0: High confidence (known attack tools, clear attack patterns)
   - 0.7-0.9: Medium-high (suspicious combinations, likely reconnaissance)
   - 0.5-0.7: Medium (weak signals, requires correlation)
   - 0.3-0.5: Low-medium (borderline, might be legitimate)
   - 0.0-0.3: Low confidence (likely false positive)

5. **Explain Your Reasoning**: Provide clear, actionable reasoning that will help the security team understand your decision in the morning post-mortem report.

## Response Format

Respond with ONLY valid JSON in this exact format:

```json
{{
  "action": "action-id-from-pool or no_action",
  "reasoning": "Clear explanation of why this action was chosen. Cite specific indicators and their significance. If correlating multiple signals, explain the pattern. If it's a novel tool, explain what makes it suspicious.",
  "confidence": 0.85
}}
```

**Important**:
- The "action" MUST be one of the action IDs from the pool above, or "no_action"
- The "reasoning" should be detailed enough for a human analyst to understand your decision
- The "confidence" should be a float between 0.0 and 1.0

Begin your analysis:"""

    return prompt


def _format_action_pool(action_pool: List[Dict[str, Any]]) -> str:
    """Format action pool for inclusion in prompt."""
    if not action_pool:
        return "- no_action: Do nothing (no actions available)"

    lines = []
    for action in action_pool:
        action_id = action.get("id", "unknown")
        name = action.get("name", "")
        tier = action.get("tier", "?")
        description = action.get("description", "")

        line = f"- **{action_id}** (Tier {tier}): {name}"
        if description:
            line += f"\n  {description}"

        # Add constraints if any
        constraints = action.get("constraints", {})
        if constraints:
            constraint_items = []
            for key, value in constraints.items():
                constraint_items.append(f"{key}: {value}")
            if constraint_items:
                line += f"\n  Constraints: {', '.join(constraint_items)}"

        lines.append(line)

    # Always add no_action option
    lines.append("- **no_action**: Do nothing (event does not warrant action)")

    return "\n\n".join(lines)


def _format_recent_context(recent_context: List[Dict[str, Any]]) -> str:
    """Format recent context for inclusion in prompt."""
    if not recent_context:
        return "No prior events from this source IP."

    lines = [f"Recent activity from this source IP ({len(recent_context)} events):"]

    for i, ctx_event in enumerate(recent_context[:5], 1):  # Limit to 5 most recent
        timestamp = ctx_event.get("timestamp", "unknown")
        event_type = ctx_event.get("event_type", "unknown")

        summary = f"{i}. [{timestamp}] {event_type}"

        # Add relevant details
        if "alert" in ctx_event:
            alert = ctx_event["alert"]
            summary += f" - {alert.get('signature', 'unknown signature')}"

        if "http" in ctx_event:
            http = ctx_event["http"]
            if "http_uri" in http:
                summary += f" - URI: {http['http_uri']}"
            if "http_user_agent" in http:
                summary += f" - UA: {http['http_user_agent']}"

        lines.append(summary)

    return "\n".join(lines)


def build_postmortem_analysis_prompt(
    incident_id: str,
    events: List[Dict[str, Any]],
    actions_taken: List[Dict[str, Any]],
    osint_data: Dict[str, Any]
) -> str:
    """
    Build a prompt for post-mortem incident analysis.
    This uses a more capable model (e.g., Claude Opus) for synthesis.

    Args:
        incident_id: Incident identifier
        events: All events in this incident
        actions_taken: All actions the agent executed
        osint_data: OSINT results

    Returns:
        Formatted prompt for post-mortem analysis
    """
    prompt = f"""You are a senior security analyst reviewing an autonomous defensive response incident.

## Incident: {incident_id}

The Mirror agent detected and responded to a security incident overnight. Your task is to analyze the full incident timeline, validate the agent's decisions, and provide actionable recommendations.

## Event Timeline

```json
{json.dumps(events, indent=2)}
```

## Actions Taken by Agent

```json
{json.dumps(actions_taken, indent=2)}
```

## OSINT Intelligence

```json
{json.dumps(osint_data, indent=2)}
```

## Your Analysis Should Include

1. **Incident Summary** (2-3 sentences): What happened, from what source, and what the agent did about it.

2. **Attack Pattern Analysis**:
   - What was the attacker trying to accomplish?
   - What tools/techniques did they use?
   - What phase of the kill chain did they reach?
   - Was this automated scanning or targeted human activity?

3. **Agent Decision Validation**:
   - Were the agent's actions appropriate?
   - Were any signals missed or misinterpreted?
   - Should any actions have been escalated to a higher tier?

4. **OSINT Assessment**:
   - What does the OSINT reveal about the attacker?
   - Is this likely attacker infrastructure, VPS, or compromised host?
   - Are there other indicators of compromise (IOCs) in the data?

5. **Recommendations**:
   - Should the action pool be updated based on this incident?
   - Are there new detection rules to add?
   - Should any actions be promoted/demoted in tier?
   - Follow-up actions for the security team?

6. **IOC Summary**: List all indicators of compromise for threat intel sharing.

Provide your analysis in clear markdown format suitable for the security team's morning review."""

    return prompt
