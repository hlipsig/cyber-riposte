"""
Flux GitOps Integration for Auto-Block Scenario

Enables real-time threat blocking while maintaining GitOps as source of truth.
Flow: Detect → Suspend Flux → Block → Commit → Human Review → Resume

Usage:
    from flux_integration import FluxDefender

    defender = FluxDefender(
        kustomization="auto-block-app",
        git_repo="/path/to/repo",
        github_repo="owner/repo"
    )

    # When threat detected
    defender.apply_emergency_block(
        attacker_ip="203.0.113.42",
        incident_id="INC-2026-06-11-001",
        threat_type="SQL Injection",
        confidence=0.98
    )
"""

import subprocess
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
import yaml
import json

logger = logging.getLogger(__name__)


class FluxDefender:
    """
    Autonomous defender that can suspend Flux, apply emergency blocks,
    commit to Git, and create review issues.
    """

    def __init__(
        self,
        kustomization: str,
        git_repo: Path,
        github_repo: str,
        confidence_threshold: float = 0.95
    ):
        """
        Initialize Flux defender.

        Args:
            kustomization: Flux kustomization name to manage
            git_repo: Path to Git repository
            github_repo: GitHub repo in "owner/name" format
            confidence_threshold: Minimum confidence to auto-act (default 0.95)
        """
        self.kustomization = kustomization
        self.git_repo = Path(git_repo)
        self.github_repo = github_repo
        self.confidence_threshold = confidence_threshold

        # Directories
        self.netpol_dir = self.git_repo / "k8s" / "network-policies"
        self.netpol_dir.mkdir(parents=True, exist_ok=True)

    def apply_emergency_block(
        self,
        attacker_ip: str,
        incident_id: str,
        threat_type: str,
        confidence: float,
        severity: str = "HIGH",
        target_labels: Dict[str, str] = None,
        namespace: str = "default"
    ) -> Optional[str]:
        """
        Apply emergency IP block with full GitOps workflow.

        Args:
            attacker_ip: IP address to block
            incident_id: Incident identifier
            threat_type: Type of threat detected
            confidence: Confidence score (0-1)
            severity: Threat severity
            target_labels: Pod labels to protect (default: all pods)
            namespace: Kubernetes namespace

        Returns:
            GitHub issue URL if successful, None otherwise
        """
        # Check confidence threshold
        if confidence < self.confidence_threshold:
            logger.warning(
                f"Confidence {confidence} below threshold {self.confidence_threshold}. "
                "Creating alert instead of auto-blocking."
            )
            return self._create_alert_only(
                attacker_ip, incident_id, threat_type, confidence
            )

        logger.info(f"⚡ Emergency block initiated for {attacker_ip}")

        try:
            # Step 1: Suspend Flux
            logger.info("1️⃣ Suspending Flux...")
            if not self._suspend_flux(incident_id, threat_type):
                logger.error("Failed to suspend Flux. Aborting emergency block.")
                return None

            # Step 2: Apply NetworkPolicy immediately
            logger.info("2️⃣ Applying emergency NetworkPolicy...")
            policy_name = f"emergency-block-{attacker_ip.replace('.', '-')}"

            if not self._apply_network_policy(
                policy_name, attacker_ip, target_labels, namespace
            ):
                logger.error("Failed to apply NetworkPolicy. Rolling back...")
                self._resume_flux()
                return None

            logger.info(f"✅ Attacker {attacker_ip} blocked in cluster")

            # Step 3: Export and commit to Git
            logger.info("3️⃣ Committing to Git...")
            policy_file = self._export_network_policy(policy_name, namespace)
            commit_sha = self._commit_defense(
                policy_file,
                incident_id,
                attacker_ip,
                threat_type,
                confidence,
                severity
            )

            if not commit_sha:
                logger.error("Failed to commit to Git. Defense still active in cluster.")
                # Don't roll back - defense is protecting us
                return None

            logger.info(f"✅ Committed to Git: {commit_sha[:8]}")

            # Step 4: Create GitHub review issue
            logger.info("4️⃣ Creating GitHub review issue...")
            issue_url = self._create_review_issue(
                incident_id,
                attacker_ip,
                threat_type,
                confidence,
                severity,
                commit_sha,
                policy_name
            )

            logger.info(f"✅ Review issue created: {issue_url}")
            logger.info(f"🎯 Emergency block complete. Awaiting human review.")

            return issue_url

        except Exception as e:
            logger.exception(f"Emergency block failed: {e}")
            logger.warning("Attempting to resume Flux...")
            self._resume_flux()
            return None

    def _suspend_flux(self, incident_id: str, reason: str) -> bool:
        """Suspend Flux kustomization."""
        try:
            # Suspend the kustomization
            result = subprocess.run(
                ["flux", "suspend", "kustomization", self.kustomization],
                capture_output=True,
                text=True,
                check=True
            )

            logger.debug(f"Flux suspend output: {result.stdout}")

            # Commit the suspension for audit trail
            self._git_commit_empty(
                f"Emergency: Flux suspended for {incident_id}\n\n"
                f"Reason: {reason}\n"
                f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
            )

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to suspend Flux: {e.stderr}")
            return False

    def _resume_flux(self) -> bool:
        """Resume Flux reconciliation."""
        try:
            result = subprocess.run(
                ["flux", "resume", "kustomization", self.kustomization],
                capture_output=True,
                text=True,
                check=True
            )

            logger.debug(f"Flux resume output: {result.stdout}")

            # Commit the resumption
            self._git_commit_empty(
                f"Flux resumed after review\n\n"
                f"Timestamp: {datetime.now(timezone.utc).isoformat()}"
            )

            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to resume Flux: {e.stderr}")
            return False

    def _apply_network_policy(
        self,
        name: str,
        block_ip: str,
        target_labels: Optional[Dict[str, str]],
        namespace: str
    ) -> bool:
        """Apply NetworkPolicy to block IP."""
        # Build NetworkPolicy
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": name,
                "namespace": namespace,
                "labels": {
                    "applied-by": "ai-defender",
                    "requires-review": "true",
                    "auto-generated": "true"
                },
                "annotations": {
                    "expires-at": self._get_expiry_time(hours=24),
                    "blocked-ip": block_ip,
                    "applied-at": datetime.now(timezone.utc).isoformat()
                }
            },
            "spec": {
                "podSelector": {
                    "matchLabels": target_labels or {}
                },
                "policyTypes": ["Ingress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "ipBlock": {
                                    "cidr": "0.0.0.0/0",
                                    "except": [f"{block_ip}/32"]
                                }
                            }
                        ]
                    }
                ]
            }
        }

        # Apply via kubectl
        try:
            result = subprocess.run(
                ["kubectl", "apply", "-f", "-"],
                input=yaml.dump(policy),
                capture_output=True,
                text=True,
                check=True
            )

            logger.debug(f"kubectl apply output: {result.stdout}")
            return True

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to apply NetworkPolicy: {e.stderr}")
            return False

    def _export_network_policy(self, name: str, namespace: str) -> Path:
        """Export NetworkPolicy from cluster to file."""
        policy_file = self.netpol_dir / f"{name}.yaml"

        try:
            result = subprocess.run(
                ["kubectl", "get", "networkpolicy", name, "-n", namespace, "-o", "yaml"],
                capture_output=True,
                text=True,
                check=True
            )

            # Clean up the YAML (remove runtime fields)
            policy = yaml.safe_load(result.stdout)

            # Remove status and managed fields
            policy.pop("status", None)
            if "metadata" in policy:
                policy["metadata"].pop("managedFields", None)
                policy["metadata"].pop("resourceVersion", None)
                policy["metadata"].pop("uid", None)
                policy["metadata"].pop("creationTimestamp", None)

            # Write cleaned YAML
            with open(policy_file, "w") as f:
                yaml.dump(policy, f, default_flow_style=False)

            logger.debug(f"Exported NetworkPolicy to {policy_file}")
            return policy_file

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to export NetworkPolicy: {e.stderr}")
            raise

    def _commit_defense(
        self,
        policy_file: Path,
        incident_id: str,
        attacker_ip: str,
        threat_type: str,
        confidence: float,
        severity: str
    ) -> Optional[str]:
        """Commit defense to Git with detailed message."""
        try:
            # Git add
            subprocess.run(
                ["git", "add", str(policy_file)],
                cwd=self.git_repo,
                check=True
            )

            # Build detailed commit message
            message = f"""AI Defense: Block {attacker_ip} - {incident_id}

Incident: {incident_id}
Threat: {threat_type} ({confidence*100:.0f}% confidence)
Target: {attacker_ip}
Severity: {severity}
Action: NetworkPolicy blocking source IP
Applied: {datetime.now(timezone.utc).isoformat()}Z
Policy: {policy_file.name}

Status: ⚠️  FLUX SUSPENDED - Awaiting human review

Review Commands:
  Approve: flux resume kustomization {self.kustomization}
  Reject:  git revert HEAD && git push && flux resume kustomization {self.kustomization}

Evidence:
  - Automated threat detection by AI Defender
  - Confidence score: {confidence*100:.1f}%
  - Severity level: {severity}

This defense was applied automatically. Human review required to make permanent.

Automatically generated by AI Defender
"""

            # Git commit
            subprocess.run(
                ["git", "commit", "-m", message],
                cwd=self.git_repo,
                check=True
            )

            # Git push
            subprocess.run(
                ["git", "push", "origin", "main"],
                cwd=self.git_repo,
                check=True
            )

            # Get commit SHA
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=self.git_repo,
                capture_output=True,
                text=True,
                check=True
            )

            return result.stdout.strip()

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to commit to Git: {e}")
            return None

    def _create_review_issue(
        self,
        incident_id: str,
        attacker_ip: str,
        threat_type: str,
        confidence: float,
        severity: str,
        commit_sha: str,
        policy_name: str
    ) -> Optional[str]:
        """Create GitHub issue for human review."""
        title = f"🚨 AI Defense: {threat_type} - {attacker_ip}"

        body = f"""## Incident: {incident_id}

### Threat Summary
- **Type**: {threat_type}
- **Source**: {attacker_ip}
- **Confidence**: {confidence*100:.0f}%
- **Severity**: {severity}

### Action Taken
Applied NetworkPolicy `{policy_name}` blocking ingress from {attacker_ip}.

### Current Status
⚠️ **Flux suspended** - Application running with emergency configuration.

### Review Required

**Option 1: Approve** (keep defense permanently)
```bash
flux resume kustomization {self.kustomization}
```
Comment: `/approve`

**Option 2: Reject** (remove defense)
```bash
git revert {commit_sha}
git push origin main
flux resume kustomization {self.kustomization}
```
Comment: `/reject`

**Option 3: Modify** (edit then approve)
1. Edit `k8s/network-policies/{policy_name}.yaml` in Git
2. Commit your changes
3. Comment: `/approve`

### Timeline
- **Detected**: {datetime.now(timezone.utc).isoformat()}Z
- **Flux Suspended**: Immediate
- **Defense Applied**: <1 second
- **Committed**: {commit_sha[:8]}

### Automated Actions
This defense was applied automatically by the AI Defender based on high-confidence threat detection.

/cc @security-team
"""

        try:
            result = subprocess.run(
                [
                    "gh", "issue", "create",
                    "--repo", self.github_repo,
                    "--title", title,
                    "--body", body,
                    "--label", "ai-defense,requires-review,high-severity"
                ],
                capture_output=True,
                text=True,
                check=True
            )

            return result.stdout.strip()

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create GitHub issue: {e.stderr}")
            return None

    def _git_commit_empty(self, message: str):
        """Create empty commit for audit trail."""
        try:
            subprocess.run(
                ["git", "commit", "--allow-empty", "-m", message],
                cwd=self.git_repo,
                check=True
            )
            subprocess.run(
                ["git", "push", "origin", "main"],
                cwd=self.git_repo,
                check=True
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to create audit commit: {e}")

    def _create_alert_only(
        self,
        attacker_ip: str,
        incident_id: str,
        threat_type: str,
        confidence: float
    ) -> Optional[str]:
        """Create alert without auto-blocking (below confidence threshold)."""
        title = f"⚠️ Threat Alert: {threat_type} - {attacker_ip}"

        body = f"""## Incident: {incident_id}

### Threat Summary
- **Type**: {threat_type}
- **Source**: {attacker_ip}
- **Confidence**: {confidence*100:.0f}%

### Action Taken
**None** - Confidence below auto-block threshold ({self.confidence_threshold*100:.0f}%).

### Manual Review Required
Please review and decide whether to block this IP manually.

**To block manually**:
```bash
kubectl apply -f - <<YAML
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: manual-block-{attacker_ip.replace('.', '-')}
spec:
  podSelector: {{}}
  policyTypes:
  - Ingress
  ingress:
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - {attacker_ip}/32
YAML
```

/cc @security-team
"""

        try:
            result = subprocess.run(
                [
                    "gh", "issue", "create",
                    "--repo", self.github_repo,
                    "--title", title,
                    "--body", body,
                    "--label", "threat-alert,manual-review,medium-severity"
                ],
                capture_output=True,
                text=True,
                check=True
            )

            return result.stdout.strip()

        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to create alert issue: {e.stderr}")
            return None

    def _get_expiry_time(self, hours: int = 24) -> str:
        """Calculate expiry timestamp."""
        from datetime import timedelta
        expiry = datetime.now(timezone.utc) + timedelta(hours=hours)
        return expiry.isoformat()


# Example usage
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    defender = FluxDefender(
        kustomization="auto-block-app",
        git_repo=Path("/path/to/cyber-riposte"),
        github_repo="hlipsig/cyber-riposte",
        confidence_threshold=0.95
    )

    # Simulate high-confidence threat detection
    issue_url = defender.apply_emergency_block(
        attacker_ip="203.0.113.42",
        incident_id="INC-2026-06-11-001",
        threat_type="SQL Injection",
        confidence=0.98,
        severity="HIGH",
        target_labels={"app": "web-service"}
    )

    if issue_url:
        print(f"✅ Emergency block applied. Review at: {issue_url}")
    else:
        print("❌ Emergency block failed")
