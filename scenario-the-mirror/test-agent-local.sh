#!/bin/bash
# Quick local test of the agent (before building container)

set -e

echo "=== Testing The Mirror Agent Locally ==="
echo

echo "1. Testing imports..."
python3 -c "from agent.config import Config; from agent.audit import AuditLog; from agent.detector import detect_recon; from agent.executor import execute_redirect; print('✓ All imports successful')"
echo

echo "2. Testing configuration..."
python3 -c "from agent.config import Config; warnings = Config.validate(); print(f'Config validation: {len(warnings)} warnings'); [print(f'  - {w}') for w in warnings]"
echo

echo "3. Testing detection logic..."
python3 << 'PYTHON_EOF'
from agent.detector import detect_recon

# Test event with both IDS alert and suspicious UA
test_event = {
    "event_type": "alert",
    "src_ip": "203.0.113.42",
    "timestamp": "2024-06-15T03:14:07Z",
    "alert": {
        "signature": "ET SCAN Nmap Scripting Engine",
        "category": "Attempted Recon",
        "severity": 2
    },
    "http": {
        "http_user_agent": "Nmap Scripting Engine"
    }
}

detection = detect_recon(test_event)
if detection:
    print(f"✓ Detection successful:")
    print(f"  - IP: {detection['src_ip']}")
    print(f"  - Confidence: {detection['confidence']:.2f}")
    print(f"  - Signals: {len(detection['signals'])}")
    print(f"  - Signature: {detection['signature']}")
else:
    print("✗ Detection failed")
    exit(1)
PYTHON_EOF
echo

echo "4. Checking required files..."
for file in action-pool.yaml suspicious-user-agents.yaml audit-log-schema.json; do
    if [ -f "$file" ]; then
        echo "  ✓ $file"
    else
        echo "  ✗ $file MISSING"
        exit 1
    fi
done
echo

echo "5. Checking OSINT modules..."
for module in osint-modules/*.py; do
    if [ -f "$module" ]; then
        echo "  ✓ $(basename $module)"
    fi
done
echo

echo "=== All local tests passed! ==="
echo
echo "Next steps:"
echo "1. Build container: docker build -t mirror-agent:test ."
echo "2. Run container: docker run --rm -it mirror-agent:test"
echo "3. Deploy to OpenShift: kubectl apply -f k8s/"
