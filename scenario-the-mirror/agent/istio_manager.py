"""
Istio Manager - Dynamic VirtualService manipulation for traffic redirection.

Phase 2: Automatically redirect detected attackers to honeypot using Istio service mesh.
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional

from kubernetes import client, config
from kubernetes.client.rest import ApiException

logger = logging.getLogger(__name__)


class IstioManager:
    """
    Manages Istio VirtualServices for attacker traffic redirection.

    Features:
    - Create VirtualService to redirect attacker IP to honeypot
    - Update existing redirects
    - Delete expired redirects (cleanup)
    - Template-based VirtualService generation
    """

    def __init__(self, namespace=None, template_path=None):
        """
        Initialize Istio manager.

        Args:
            namespace: Kubernetes namespace (default: the-mirror)
            template_path: Path to VirtualService template
        """
        self.namespace = namespace or os.getenv('KUBERNETES_NAMESPACE', 'the-mirror')
        self.template_path = template_path or self._get_template_path()

        # Initialize Kubernetes client
        try:
            # Try in-cluster config first (when running in pod)
            config.load_incluster_config()
            logger.info("Loaded in-cluster Kubernetes config")
        except config.ConfigException:
            # Fall back to kubeconfig (when running locally)
            config.load_kube_config()
            logger.info("Loaded kubeconfig")

        self.custom_api = client.CustomObjectsApi()
        self.core_api = client.CoreV1Api()

        # Istio API group and version
        self.istio_group = "networking.istio.io"
        self.istio_version = "v1beta1"
        self.vs_plural = "virtualservices"

    def _get_template_path(self) -> Path:
        """Get path to VirtualService template."""
        base_dir = Path(__file__).parent.parent
        template_path = base_dir / "templates" / "virtual-service-attacker.yaml"

        if not template_path.exists():
            logger.warning(f"Template not found: {template_path}")

        return template_path

    def create_redirect(
        self,
        incident_id: str,
        attacker_ip: str,
        honeypot_host: str = "honeypot-service",
        honeypot_port: int = 80,
        ttl_hours: int = 1
    ) -> bool:
        """
        Create VirtualService to redirect attacker traffic to honeypot.

        Args:
            incident_id: Incident ID (e.g., INC-20260611-1840)
            attacker_ip: Attacker source IP address
            honeypot_host: Honeypot service hostname
            honeypot_port: Honeypot service port
            ttl_hours: How long redirect should last (auto-cleanup)

        Returns:
            True if created successfully, False otherwise
        """
        vs_name = f"mirror-redirect-{incident_id.lower()}"

        logger.info(f"Creating VirtualService redirect: {vs_name}")
        logger.info(f"  Attacker IP: {attacker_ip}")
        logger.info(f"  Honeypot: {honeypot_host}:{honeypot_port}")
        logger.info(f"  TTL: {ttl_hours} hours")

        # Check if already exists
        try:
            existing = self.custom_api.get_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                name=vs_name
            )
            logger.info(f"VirtualService {vs_name} already exists, updating...")
            return self._update_redirect(vs_name, attacker_ip, honeypot_host, honeypot_port, ttl_hours)
        except ApiException as e:
            if e.status != 404:
                logger.error(f"Error checking existing VirtualService: {e}")
                return False

        # Build VirtualService from template
        vs_manifest = self._build_virtualservice(
            incident_id=incident_id,
            attacker_ip=attacker_ip,
            honeypot_host=honeypot_host,
            honeypot_port=honeypot_port,
            ttl_hours=ttl_hours
        )

        # Create VirtualService
        try:
            self.custom_api.create_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                body=vs_manifest
            )
            logger.info(f"✅ VirtualService created: {vs_name}")
            return True
        except ApiException as e:
            logger.error(f"Failed to create VirtualService: {e}")
            return False

    def _build_virtualservice(
        self,
        incident_id: str,
        attacker_ip: str,
        honeypot_host: str,
        honeypot_port: int,
        ttl_hours: int
    ) -> Dict:
        """
        Build VirtualService manifest from template.

        Returns dict ready for Kubernetes API.
        """
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(hours=ttl_hours)

        # Load template if available, otherwise use inline template
        if self.template_path.exists():
            template_str = self.template_path.read_text()
        else:
            template_str = self._get_inline_template()

        # Replace template variables
        manifest_str = template_str.format(
            incident_id=incident_id.lower(),
            attacker_ip=attacker_ip,
            created_at=now.isoformat(),
            expires_at=expires_at.isoformat(),
            honeypot_host=honeypot_host,
            honeypot_port=honeypot_port
        )

        # Parse YAML
        import yaml
        manifest = yaml.safe_load(manifest_str)

        return manifest

    def _get_inline_template(self) -> str:
        """Fallback inline template if file not found."""
        return """
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata:
  name: mirror-redirect-{incident_id}
  namespace: the-mirror
  labels:
    app: the-mirror
    component: redirect
    managed-by: mirror-agent
    incident-id: "{incident_id}"
  annotations:
    mirror.cyber-riposte.dev/attacker-ip: "{attacker_ip}"
    mirror.cyber-riposte.dev/created-at: "{created_at}"
    mirror.cyber-riposte.dev/expires-at: "{expires_at}"
spec:
  hosts:
  - "*"
  gateways:
  - mirror-gateway
  http:
  - match:
    - headers:
        x-forwarded-for:
          exact: "{attacker_ip}"
    route:
    - destination:
        host: {honeypot_host}
        port:
          number: {honeypot_port}
    headers:
      response:
        add:
          x-mirror-honeypot: "true"
          x-mirror-incident: "{incident_id}"
"""

    def _update_redirect(
        self,
        vs_name: str,
        attacker_ip: str,
        honeypot_host: str,
        honeypot_port: int,
        ttl_hours: int
    ) -> bool:
        """Update existing VirtualService."""
        try:
            # Get current manifest
            current = self.custom_api.get_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                name=vs_name
            )

            # Update annotations
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(hours=ttl_hours)

            if 'annotations' not in current['metadata']:
                current['metadata']['annotations'] = {}

            current['metadata']['annotations']['mirror.cyber-riposte.dev/expires-at'] = expires_at.isoformat()

            # Update VirtualService
            self.custom_api.patch_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                name=vs_name,
                body=current
            )

            logger.info(f"✅ VirtualService updated: {vs_name}")
            return True

        except ApiException as e:
            logger.error(f"Failed to update VirtualService: {e}")
            return False

    def delete_redirect(self, incident_id: str) -> bool:
        """
        Delete VirtualService redirect.

        Args:
            incident_id: Incident ID

        Returns:
            True if deleted successfully
        """
        vs_name = f"mirror-redirect-{incident_id.lower()}"

        try:
            self.custom_api.delete_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                name=vs_name
            )
            logger.info(f"✅ VirtualService deleted: {vs_name}")
            return True
        except ApiException as e:
            if e.status == 404:
                logger.warning(f"VirtualService not found: {vs_name}")
                return True
            logger.error(f"Failed to delete VirtualService: {e}")
            return False

    def cleanup_expired_redirects(self) -> int:
        """
        Delete expired VirtualService redirects.

        Returns:
            Number of redirects cleaned up
        """
        logger.info("Cleaning up expired VirtualService redirects...")

        try:
            # List all Mirror-managed VirtualServices
            vs_list = self.custom_api.list_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                label_selector="managed-by=mirror-agent"
            )

            now = datetime.now(timezone.utc)
            cleaned = 0

            for vs in vs_list.get('items', []):
                annotations = vs.get('metadata', {}).get('annotations', {})
                expires_at_str = annotations.get('mirror.cyber-riposte.dev/expires-at')

                if not expires_at_str:
                    continue

                try:
                    expires_at = datetime.fromisoformat(expires_at_str.replace('Z', '+00:00'))

                    if now > expires_at:
                        vs_name = vs['metadata']['name']
                        logger.info(f"Deleting expired redirect: {vs_name}")

                        self.custom_api.delete_namespaced_custom_object(
                            group=self.istio_group,
                            version=self.istio_version,
                            namespace=self.namespace,
                            plural=self.vs_plural,
                            name=vs_name
                        )
                        cleaned += 1

                except Exception as e:
                    logger.warning(f"Error parsing expiry for {vs['metadata']['name']}: {e}")

            if cleaned > 0:
                logger.info(f"✅ Cleaned up {cleaned} expired redirects")
            else:
                logger.info("No expired redirects to clean up")

            return cleaned

        except ApiException as e:
            logger.error(f"Failed to list VirtualServices: {e}")
            return 0

    def list_active_redirects(self) -> list:
        """
        List all active attacker redirects.

        Returns:
            List of dicts with redirect info
        """
        try:
            vs_list = self.custom_api.list_namespaced_custom_object(
                group=self.istio_group,
                version=self.istio_version,
                namespace=self.namespace,
                plural=self.vs_plural,
                label_selector="managed-by=mirror-agent"
            )

            redirects = []
            now = datetime.now(timezone.utc)

            for vs in vs_list.get('items', []):
                metadata = vs.get('metadata', {})
                annotations = metadata.get('annotations', {})

                attacker_ip = annotations.get('mirror.cyber-riposte.dev/attacker-ip')
                created_at = annotations.get('mirror.cyber-riposte.dev/created-at')
                expires_at = annotations.get('mirror.cyber-riposte.dev/expires-at')

                if attacker_ip:
                    redirects.append({
                        'name': metadata['name'],
                        'incident_id': metadata.get('labels', {}).get('incident-id'),
                        'attacker_ip': attacker_ip,
                        'created_at': created_at,
                        'expires_at': expires_at,
                        'active': True  # Could check expiry here
                    })

            return redirects

        except ApiException as e:
            logger.error(f"Failed to list VirtualServices: {e}")
            return []


# Singleton instance
_istio_manager = None


def get_istio_manager() -> IstioManager:
    """Get or create global Istio manager instance."""
    global _istio_manager
    if _istio_manager is None:
        _istio_manager = IstioManager()
    return _istio_manager


# Test / example usage
if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)

    manager = IstioManager()

    # Create test redirect
    print("Creating test redirect...")
    success = manager.create_redirect(
        incident_id="INC-TEST-001",
        attacker_ip="1.2.3.4",
        honeypot_host="honeypot-service",
        honeypot_port=80,
        ttl_hours=1
    )
    print(f"Result: {'✅ Success' if success else '❌ Failed'}")

    # List active redirects
    print("\nActive redirects:")
    redirects = manager.list_active_redirects()
    for r in redirects:
        print(f"  - {r['attacker_ip']} -> {r['incident_id']}")

    # Cleanup expired
    print("\nCleaning up expired redirects...")
    cleaned = manager.cleanup_expired_redirects()
    print(f"Cleaned: {cleaned}")
