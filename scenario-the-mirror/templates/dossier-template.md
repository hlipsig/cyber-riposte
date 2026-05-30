# Intelligence Dossier: {{ attacker_ip }}

**Generated:** {{ timestamp }}
**Trigger:** {{ trigger_signature }}
**Agent:** The Mirror (cyber-riposte)

---

## Summary

Attacker `{{ attacker_ip }}` was detected performing reconnaissance against our infrastructure. Traffic was redirected to a honeypot while passive OSINT was collected. This dossier contains everything publicly available about the attacker's infrastructure.

---

## WHOIS

- **Owner:** {{ whois_org }}
- **ASN:** {{ whois_asn }}
- **Net range:** {{ whois_net_range }}
- **Country:** {{ whois_country }}
- **Abuse contact:** {{ whois_abuse_contact }}
- **Registration date:** {{ whois_reg_date }}

## Reverse DNS

- **PTR record:** {{ rdns_ptr }}
- **Hosting provider:** {{ rdns_provider }}

## Shodan — Attacker's Infrastructure

- **Open ports:** {{ shodan_ports }}
- **Operating system:** {{ shodan_os }}
- **Service banners:**

{{ shodan_banners }}

- **Known vulnerabilities:** {{ shodan_vulns }}

## Certificate Transparency

Domains with TLS certificates issued to this IP's hostnames:

{{ ct_domains }}

## Honeypot Interaction Summary

- **Session duration:** {{ session_duration }}
- **Commands entered:** {{ command_count }}
- **Credentials attempted:** {{ cred_count }}
- **Files downloaded:** {{ files_downloaded }}
- **Tools identified:** {{ tools_identified }}

## IOCs for Threat Intel Platforms

```json
{{ ioc_json }}
```

## Recommended Actions

1. Permanent block rule for `{{ attacker_ip }}` (included in this PR)
2. Block associated infrastructure: {{ associated_ips }}
3. Report to abuse contact: {{ whois_abuse_contact }}
4. Ingest IOCs into threat intel platform
