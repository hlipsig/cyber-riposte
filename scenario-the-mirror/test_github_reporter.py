#!/usr/bin/env python3
"""
Test GitHub reporter
"""
import sys
sys.path.insert(0, 'agent')

from github_reporter import create_incident_issue

# Test data (simulated incident)
test_incident = {
    'attacker_ip': '1.2.3.4',
    'detection_signature': 'ET SCAN Nmap Scripting Engine User-Agent Detected',
    'detection_confidence': 0.98,
    'osint_data': {
        'organization': 'Evil Corp Hosting',
        'asn': 'AS12345',
        'country': 'RU',
        'hosting_provider': 'DigitalOcean',
        'open_ports': [22, 80, 443, 3389, 8080],
        'services': [
            {'port': 22, 'service': 'OpenSSH 8.9'},
            {'port': 80, 'service': 'nginx/1.24.0'},
            {'port': 3389, 'service': 'RDP'},
        ],
        'vulnerabilities': ['CVE-2023-12345', 'CVE-2024-67890'],
        'ptr_record': 'vps-evil-123.digitalocean.com',
        'abuse_contact': 'abuse@example.com',
        'geolocation': {
            'country': 'Russia',
            'city': 'Moscow',
        }
    },
    'actions_taken': [
        {'name': 'Redirect to honeypot', 'result': 'success', 'tier': 1},
        {'name': 'Run passive OSINT', 'result': 'success', 'tier': 1},
        {'name': 'Temporary IP block', 'result': 'success', 'tier': 1},
    ],
    'timeline': [
        {'timestamp': '2026-06-11 18:40:14 UTC', 'description': 'Nmap scan detected'},
        {'timestamp': '2026-06-11 18:40:15 UTC', 'description': 'Redirected to honeypot'},
        {'timestamp': '2026-06-11 18:40:30 UTC', 'description': 'OSINT collection completed'},
        {'timestamp': '2026-06-11 18:41:00 UTC', 'description': '1-hour IP block applied'},
    ]
}

print("Testing GitHub reporter...")
print("=" * 60)

issue_url = create_incident_issue('INC-TEST-20260611-TEST01', test_incident)

if issue_url:
    print(f"\n✅ GitHub issue created!")
    print(f"URL: {issue_url}")
else:
    print(f"\n❌ Failed to create GitHub issue")
    print("Note: Set GITHUB_TOKEN environment variable for real issue creation")
    print("      Without token, the system will simulate issue creation")

print("\n" + "=" * 60)
print("Test complete!")
