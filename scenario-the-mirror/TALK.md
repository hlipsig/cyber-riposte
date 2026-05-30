# The Mirror — 5-Minute Talk Version

## The Fencing Metaphor

In fencing, a **riposte** is the counterattack you launch immediately after parrying your opponent's blade. You don't just block — you use their forward momentum against them. The harder they lunge, the more exposed they are to your counter.

**The Mirror** is a digital riposte. When an attacker scans your infrastructure, their probe *is* the opening. Every packet they send you reveals something about *them* — their IP, their tools, their infrastructure, their timing. The harder they push, the more they expose.

## The Story (5 minutes)

### Act 1: The Lunge (~1 min)
An attacker begins scanning your perimeter. Port scans, directory brute-forcing, version fingerprinting. Normal Tuesday.

Your AI agent sees it in the telemetry. But instead of just blocking the IP, it recognizes an opportunity.

### Act 2: The Parry (~1 min)
The agent reroutes the attacker to a honeypot — they keep "working" against what looks like your real infrastructure. They think they're making progress. They're not.

Meanwhile, the agent has already started its counterintelligence work — using the attacker's own source IP to learn everything publicly available about them.

### Act 3: The Riposte (~2 min)
While the attacker probes the honeypot, the agent runs passive OSINT on the attacker's IP:

- **WHOIS** → who owns this IP range? A VPS provider? A compromised residential ISP?
- **Reverse DNS** → does this IP have a hostname? Does it tell us anything?
- **Shodan** → what services is the *attacker's* machine running? Open ports? Banners?
- **Certificate Transparency** → any TLS certs issued to domains on this IP? Reveals their other infrastructure.

The attacker scanned us. We scanned them back. Their momentum is now our intelligence.

### Act 4: The Touch (~1 min)
The agent opens a PR with two things:
1. A block/reroute rule for the attacker's IP
2. A full **intelligence dossier** on the attacker's infrastructure

The security team reviews a PR that doesn't just say "block this IP" — it says "here's who they are, what they're running, and what else they own."

**One scan. Two dossiers. Only one of them knew it was happening.**

## Key Slide

```
Attacker                          Defender (AI Agent)
────────                          ──────────────────
Scans your ports        ───▶      Detects scan
                                  Reroutes to honeypot
                        ◀───      Runs OSINT on attacker IP
Probes honeypot         ───▶      Logs all TTPs
                                  WHOIS, rDNS, Shodan, CT
                        ◀───      Builds attacker dossier
Gets blocked            ◀───      Opens PR: block + intel report

They brought a scanner.
You brought a mirror.
```
