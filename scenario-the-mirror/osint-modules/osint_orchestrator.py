"""
OSINT Orchestrator - Coordinates all passive intelligence gathering.

Runs all OSINT modules in parallel, caches results, and aggregates findings.
"""

import logging
import threading
from datetime import datetime, timezone, timedelta
from typing import Dict, Optional

logger = logging.getLogger(__name__)


class OSINTOrchestrator:
    """
    Coordinates passive intelligence gathering on attacker IPs.
    
    Features:
    - Parallel execution of all OSINT modules
    - Result caching (24-hour TTL)
    - Graceful fallback on module failures
    - Structured output for database storage
    """
    
    def __init__(self, cache_ttl_hours=24):
        self.cache = {}
        self.cache_ttl = timedelta(hours=cache_ttl_hours)
        self.lock = threading.Lock()
        
    def gather_intelligence(self, ip: str) -> Dict:
        """
        Run all OSINT modules on an IP address.
        
        Returns aggregated intelligence dict ready for database storage.
        """
        # Check cache first
        cached = self._get_cached(ip)
        if cached:
            logger.info(f"OSINT cache hit for {ip}")
            return cached
        
        logger.info(f"Gathering OSINT for {ip}...")
        
        # Run all modules in parallel
        results = {}
        threads = []
        
        modules = [
            ('shodan', self._run_shodan),
            ('whois', self._run_whois),
            ('reverse_dns', self._run_reverse_dns),
            ('cert_transparency', self._run_cert_transparency),
            ('geoip', self._run_geoip),
        ]
        
        def run_module(name, func):
            try:
                results[name] = func(ip)
                logger.info(f"✅ {name} completed for {ip}")
            except Exception as e:
                logger.error(f"❌ {name} failed for {ip}: {e}")
                results[name] = {"error": str(e)}
        
        for name, func in modules:
            t = threading.Thread(target=run_module, args=(name, func))
            t.start()
            threads.append(t)
        
        # Wait for all modules (with timeout)
        for t in threads:
            t.join(timeout=30)
        
        # Aggregate results
        aggregated = self._aggregate_results(ip, results)
        
        # Cache for future lookups
        self._cache_result(ip, aggregated)
        
        return aggregated
    
    def _run_shodan(self, ip: str) -> Dict:
        """Run Shodan lookup."""
        try:
            from shodan_lookup import shodan_lookup
        except ImportError:
            from osint_modules.shodan_lookup import shodan_lookup
        return shodan_lookup(ip)

    def _run_whois(self, ip: str) -> Dict:
        """Run WHOIS lookup."""
        try:
            from whois_lookup import whois_lookup
        except ImportError:
            from osint_modules.whois_lookup import whois_lookup
        return whois_lookup(ip)

    def _run_reverse_dns(self, ip: str) -> Dict:
        """Run reverse DNS lookup."""
        try:
            from reverse_dns import reverse_dns
        except ImportError:
            from osint_modules.reverse_dns import reverse_dns
        return reverse_dns(ip)

    def _run_cert_transparency(self, ip: str) -> Dict:
        """Run certificate transparency lookup."""
        try:
            try:
                from cert_transparency import cert_transparency_lookup
            except ImportError:
                from osint_modules.cert_transparency import cert_transparency_lookup
            return cert_transparency_lookup(ip)
        except Exception as e:
            logger.warning(f"Cert transparency not available: {e}")
            return {"error": "module not available"}
    
    def _run_geoip(self, ip: str) -> Dict:
        """Run GeoIP lookup."""
        try:
            import geoip2.database
            import os
            
            db_path = os.getenv('GEOIP_DB_PATH', '/usr/share/GeoIP/GeoLite2-City.mmdb')
            if not os.path.exists(db_path):
                return {
                    "country": "unknown",
                    "city": "unknown",
                    "latitude": None,
                    "longitude": None,
                    "_note": "GeoIP database not found"
                }
            
            with geoip2.database.Reader(db_path) as reader:
                response = reader.city(ip)
                return {
                    "country": response.country.name,
                    "country_code": response.country.iso_code,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "timezone": response.location.time_zone,
                }
        except Exception as e:
            logger.warning(f"GeoIP lookup failed: {e}")
            return {"error": str(e)}
    
    def _aggregate_results(self, ip: str, results: Dict) -> Dict:
        """
        Aggregate all OSINT results into structured format.
        
        Returns dict ready for JSON storage in database.
        """
        aggregated = {
            "ip": ip,
            "collected_at": datetime.now(timezone.utc).isoformat(),
            "modules_run": list(results.keys()),
            "modules_succeeded": [k for k, v in results.items() if "error" not in v],
            "modules_failed": [k for k, v in results.items() if "error" in v],
        }
        
        # Shodan data
        if "shodan" in results and "error" not in results["shodan"]:
            shodan = results["shodan"]
            aggregated["open_ports"] = shodan.get("open_ports", [])
            aggregated["os"] = shodan.get("os", "unknown")
            aggregated["services"] = shodan.get("banners", [])
            aggregated["vulnerabilities"] = shodan.get("vulns", [])
            aggregated["hostnames"] = shodan.get("hostnames", [])
            aggregated["last_seen_shodan"] = shodan.get("last_update")
        
        # WHOIS data
        if "whois" in results and "error" not in results["whois"]:
            whois = results["whois"]
            aggregated["organization"] = whois.get("org", "unknown")
            aggregated["asn"] = whois.get("asn", "unknown")
            aggregated["net_range"] = whois.get("net_range", "unknown")
            aggregated["country"] = whois.get("country", "unknown")
            aggregated["abuse_contact"] = whois.get("abuse_contact")
            aggregated["registration_date"] = whois.get("registration_date")
        
        # Reverse DNS
        if "reverse_dns" in results and "error" not in results["reverse_dns"]:
            rdns = results["reverse_dns"]
            aggregated["ptr_record"] = rdns.get("ptr")
            aggregated["hosting_provider"] = rdns.get("provider_guess", "unknown")
        
        # Certificate Transparency
        if "cert_transparency" in results and "error" not in results["cert_transparency"]:
            ct = results["cert_transparency"]
            aggregated["related_domains"] = ct.get("domains", [])
        
        # GeoIP
        if "geoip" in results and "error" not in results["geoip"]:
            geo = results["geoip"]
            aggregated["geolocation"] = {
                "country": geo.get("country"),
                "city": geo.get("city"),
                "coordinates": {
                    "lat": geo.get("latitude"),
                    "lon": geo.get("longitude"),
                },
                "timezone": geo.get("timezone"),
            }
        
        # Add raw module results for forensics
        aggregated["raw_modules"] = results
        
        return aggregated
    
    def _get_cached(self, ip: str) -> Optional[Dict]:
        """Check if we have cached OSINT data for this IP."""
        with self.lock:
            if ip not in self.cache:
                return None
            
            cached_at, data = self.cache[ip]
            
            # Check if cache is expired
            if datetime.now(timezone.utc) - cached_at > self.cache_ttl:
                del self.cache[ip]
                return None
            
            return data
    
    def _cache_result(self, ip: str, data: Dict):
        """Cache OSINT results."""
        with self.lock:
            self.cache[ip] = (datetime.now(timezone.utc), data)
            logger.debug(f"Cached OSINT for {ip} (TTL: {self.cache_ttl})")


# Global singleton instance
_orchestrator = None


def get_osint_orchestrator() -> OSINTOrchestrator:
    """Get or create the global OSINT orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = OSINTOrchestrator()
    return _orchestrator


def gather_intelligence(ip: str) -> Dict:
    """
    Convenience function to gather intelligence on an IP.
    
    This is the main entry point for OSINT collection.
    """
    orchestrator = get_osint_orchestrator()
    return orchestrator.gather_intelligence(ip)
