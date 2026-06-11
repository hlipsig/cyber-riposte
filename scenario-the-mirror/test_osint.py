#!/usr/bin/env python3
"""
Quick test of OSINT orchestrator
"""
import sys
sys.path.insert(0, 'osint-modules')

from osint_orchestrator import gather_intelligence

# Test with a public IP (Cloudflare DNS)
test_ip = "1.1.1.1"

print(f"Testing OSINT orchestrator on {test_ip}...")
print("=" * 60)

result = gather_intelligence(test_ip)

print(f"\nModules run: {result.get('modules_run', [])}")
print(f"Modules succeeded: {result.get('modules_succeeded', [])}")
print(f"Modules failed: {result.get('modules_failed', [])}")

print("\nKey intelligence:")
if result.get('organization'):
    print(f"  Organization: {result['organization']}")
if result.get('asn'):
    print(f"  ASN: {result['asn']}")
if result.get('hosting_provider'):
    print(f"  Provider: {result['hosting_provider']}")
if result.get('open_ports'):
    print(f"  Open ports: {result['open_ports']}")
if result.get('geolocation'):
    geo = result['geolocation']
    print(f"  Location: {geo.get('city')}, {geo.get('country')}")

print("\n✅ OSINT orchestrator test complete!")
