#!/bin/bash
# Build and deploy LLM server to OpenShift

set -e

echo "Building LLM Server..."
echo "======================"

# Check if oc is logged in
if ! oc whoami &> /dev/null; then
    echo "Error: Not logged into OpenShift. Run 'oc login' first."
    exit 1
fi

# Check if namespace exists
NAMESPACE="the-mirror"
if ! oc get namespace "$NAMESPACE" &> /dev/null; then
    echo "Creating namespace: $NAMESPACE"
    oc create namespace "$NAMESPACE"
fi

# Switch to namespace
oc project "$NAMESPACE"

# Create BuildConfig if it doesn't exist
if ! oc get bc/llm-server &> /dev/null; then
    echo "Creating BuildConfig..."
    oc new-build --binary --name=llm-server -l app=llm-server
else
    echo "BuildConfig already exists"
fi

# Start build from current directory
echo "Starting build (this will take ~5-10 minutes to download model)..."
oc start-build llm-server --from-dir=. --follow

# Deploy if not already deployed
if ! oc get deployment/llm-server &> /dev/null; then
    echo "Deploying LLM server..."
    oc apply -f ../k8s/llm-server-deployment.yaml
else
    echo "Deployment already exists, triggering rollout..."
    oc rollout restart deployment/llm-server
fi

# Wait for rollout
echo "Waiting for deployment to be ready..."
oc rollout status deployment/llm-server --timeout=5m

# Test health
echo ""
echo "Testing health endpoint..."
POD=$(oc get pod -l app=llm-server -o jsonpath='{.items[0].metadata.name}')
if [ -n "$POD" ]; then
    oc exec "$POD" -- curl -s http://localhost:8000/health | jq .
    echo ""
    echo "✅ LLM server deployed successfully!"
    echo ""
    echo "Service URL: http://llm-server:8000"
    echo ""
    echo "To test from Mirror agent:"
    echo "  oc exec -it deployment/mirror-agent -- curl http://llm-server:8000/health"
else
    echo "❌ No pod found"
    exit 1
fi
