## The Mirror — Counter-Reconnaissance Report

Attacker `{{ attacker_ip }}` detected performing reconnaissance ({{ trigger_signature }}).

### Actions Taken

1. **Redirected** traffic to honeypot at `{{ honeypot_ip }}`
2. **Collected** passive OSINT (WHOIS, rDNS, Shodan, CT logs)
3. **Logged** attacker interactions with honeypot
4. **Compiled** full intelligence dossier

### Quick Intel

| | |
|---|---|
| **IP Owner** | {{ whois_org }} ({{ whois_country }}) |
| **ASN** | {{ whois_asn }} |
| **Open Ports** | {{ shodan_ports }} |
| **Hosting** | {{ rdns_provider }} |
| **Associated Domains** | {{ ct_domain_count }} found |

### Files in This PR

- `redirect-{{ attacker_ip_dashed }}.nft` — nftables DNAT rule
- `dossier-{{ attacker_ip_dashed }}.md` — full intelligence report

**They scanned us. We scanned them back.**

---
*Opened by cyber-riposte agent (The Mirror)*
