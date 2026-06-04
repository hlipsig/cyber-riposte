

# LLM Integration Guide for The Mirror

The Mirror supports **hybrid detection**: combining fast rule-based detection with intelligent LLM reasoning for ambiguous cases and novel attacks.

---

## Quick Start

### Option 1: Rules Only (Default, No LLM)

**Use when**: You want zero API costs, offline operation, and deterministic results.

```bash
# No configuration needed - this is the default
env:
  - name: LLM_BACKEND
    value: "rules"
```

**Pros**: Fast (<1ms), free, deterministic, works offline  
**Cons**: Only catches known patterns, no reasoning for post-mortems

---

### Option 2: Claude API (Cloud-Based, Best Quality)

**Use when**: You want the best reasoning quality and don't mind API costs (~$10-50/month).

```bash
# Create secret with Claude API key
oc create secret generic mirror-agent-secrets \
  --from-literal=ANTHROPIC_API_KEY=sk-ant-your-key-here \
  -n cyber-riposte

# Use Claude deployment
oc apply -f k8s/agent-deployment-llm-claude.yaml
```

**Config**:
```yaml
env:
  - name: LLM_BACKEND
    value: "hybrid"  # Rules + Claude for ambiguous cases
  - name: CLAUDE_MODEL
    value: "claude-sonnet-4-6"  # Fast, cost-effective
  - name: ANTHROPIC_API_KEY
    valueFrom:
      secretKeyRef:
        name: mirror-agent-secrets
        key: ANTHROPIC_API_KEY
```

**Pros**: Best reasoning, catches novel attacks, rich explanations  
**Cons**: Costs money (~$0.003 per event), ~500ms latency, requires internet

---

### Option 3: Hugging Face Local (GPU Required, Free)

**Use when**: You want LLM intelligence without API costs and have GPU nodes.

```bash
# Deploy to GPU node
oc apply -f k8s/agent-deployment-llm-huggingface.yaml
```

**Config**:
```yaml
env:
  - name: LLM_BACKEND
    value: "hybrid"
  - name: HF_MODEL
    value: "meta-llama/Llama-3.1-8B-Instruct"  # Recommended
  - name: HF_DEVICE
    value: "cuda"  # GPU inference

resources:
  limits:
    nvidia.com/gpu: 1
    memory: "24Gi"
```

**Pros**: Free (no API costs), works offline, good reasoning  
**Cons**: Requires GPU, higher memory (16-24GB), model loading time (30-60s on start)

---

### Option 4: Hugging Face API (Cloud, No GPU Needed)

**Use when**: You want HF models without running them locally.

```bash
# Get HF API token from https://huggingface.co/settings/tokens
oc create secret generic mirror-agent-secrets \
  --from-literal=HF_API_TOKEN=hf_your-token-here \
  -n cyber-riposte
```

**Config**:
```yaml
env:
  - name: LLM_BACKEND
    value: "hybrid"
  - name: HF_MODEL
    value: "meta-llama/Llama-3.1-8B-Instruct"
  - name: HF_USE_API
    value: "true"  # Use HF Inference API
  - name: HF_API_TOKEN
    valueFrom:
      secretKeyRef:
        name: mirror-agent-secrets
        key: HF_API_TOKEN
```

**Pros**: No GPU needed, free tier available, works like Claude API  
**Cons**: API rate limits, slower than local GPU

---

## How Hybrid Detection Works

```
┌─────────────────────────────────────────────────────────────┐
│ Event arrives (Suricata EVE alert, HTTP request, etc.)     │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────────┐
                    │  Rule-Based Detector │
                    │  (Pattern Matching)  │
                    └─────────────────────┘
                              │
            ┌─────────────────┼─────────────────┐
            │                 │                 │
            ▼                 ▼                 ▼
    HIGH CONFIDENCE    MEDIUM/LOW        NO DETECTION
    (>0.85)           CONFIDENCE         
    "Nmap scan"       (0.5-0.85)         "Unknown UA"
            │           "curl/7.68.0"         │
            │                 │                 │
            │                 ▼                 │
            │         ┌──────────────────┐     │
            │         │ Consult LLM      │◄────┘
            │         │ (If available)   │
            │         └──────────────────┘
            │                 │
            │                 ▼
            │    LLM analyzes context,
            │    correlates weak signals,
            │    reasons about novel patterns
            │                 │
            └─────────────────┼─────────────────┐
                              │                  │
                              ▼                  ▼
                    ┌──────────────────┐   ┌────────────┐
                    │  LLM Decision    │   │  No Action │
                    │  + Reasoning     │   └────────────┘
                    └──────────────────┘
                              │
                              ▼
                ┌──────────────────────────────┐
                │ Execute Action from Pool     │
                │ Log LLM Reasoning in Audit   │
                └──────────────────────────────┘
```

**Strategy**:
1. **High-confidence rules** (>0.85): Trust immediately, skip LLM
2. **Medium-confidence rules** (0.5-0.85): Consult LLM for validation
3. **No rule detection**: Check heuristics, maybe consult LLM
4. **LLM unavailable**: Fall back to rules

---

## Recommended Models

### Claude API (Best Quality)

| Model | Use Case | Cost/Event | Latency | Quality |
|-------|----------|-----------|---------|---------|
| **claude-sonnet-4-6** (Recommended) | Per-event decisions | ~$0.003 | ~500ms | Excellent |
| claude-opus-4-8 | Post-mortem synthesis | ~$0.015 | ~2s | Best |
| claude-haiku-4-5 | Budget option | ~$0.001 | ~300ms | Good |

### Hugging Face Local/API

| Model | GPU Memory | Quality | License |
|-------|-----------|---------|---------|
| **meta-llama/Llama-3.1-8B-Instruct** (Recommended) | 10-12GB | Excellent | Llama 3.1 |
| mistralai/Mistral-7B-Instruct-v0.3 | 8-10GB | Very Good | Apache 2.0 |
| Qwen/Qwen2.5-7B-Instruct | 8-10GB | Very Good | Apache 2.0 |
| microsoft/Phi-3-medium-4k-instruct | 4-6GB | Good | MIT |

**Recommendation**: 
- **Best quality**: Claude Sonnet 4.6
- **Best free option**: Llama 3.1 8B on local GPU
- **Best no-GPU option**: HF API with Llama 3.1

---

## Cost Comparison

### Scenario: 10,000 events/day, 1% trigger detection (100 events/day)

**Rules Only**:
- Cost: **$0/month**
- Latency: <1ms per event

**Hybrid (Claude Sonnet 4.6)**:
- High-confidence rules: 80 events (fast path, no LLM)
- LLM consulted: 20 events/day
- Cost: **~$1.80/month** (20 events × $0.003 × 30 days)
- Latency: <1ms for 80%, ~500ms for 20%

**Hybrid (Llama 3.1 Local GPU)**:
- Cost: **$0/month** (but GPU node cost ~$200-500/month)
- Latency: <1ms for fast path, ~300-800ms for LLM
- One-time: Model download (~16GB)

**Claude Only (all events)**:
- Cost: **~$9/month** (100 events × $0.003 × 30 days)
- Latency: ~500ms for all events

**Recommendation**: Use **hybrid mode** - you get 80-90% of events through fast rules, LLM only for ambiguous cases.

---

## Example Detections

### Example 1: Novel Tool (LLM Catches, Rules Miss)

**Event**:
```json
{
  "src_ip": "203.0.113.42",
  "http_user_agent": "custom-recon-v2.7 (github.com/attacker/custom-recon)",
  "http_uri": "/api/v1/users?limit=1000"
}
```

**Rule-based**: ❌ No match for "custom-recon-v2.7"

**LLM Response**:
```json
{
  "action": "redirect-to-honeypot",
  "confidence": 0.87,
  "reasoning": "User-agent explicitly identifies as 'custom-recon' with GitHub repo link, matching pattern of offensive tools (Nuclei, httpx). Large limit parameter (1000) on user enumeration endpoint suggests bulk data extraction. Even though this exact tool isn't in our signature database, the self-identification + suspicious API usage warrants redirection to honeypot."
}
```

---

### Example 2: Weak Signal Correlation (LLM Sees Pattern, Rules Don't)

**Events** (3 sequential requests from same IP):
```json
// 03:14:07
{"http_uri": "/robots.txt", "user_agent": "curl/7.68.0"}

// 03:14:22
{"http_uri": "/.git/config", "response_code": 404, "user_agent": "curl/7.68.0"}

// 03:14:35
{"http_uri": "/admin", "response_code": 401, "user_agent": "curl/7.68.0"}
```

**Rule-based**: ❌ curl is low-confidence (0.3), no action on individual events

**LLM Response** (sees all 3 in context):
```json
{
  "action": "redirect-to-honeypot",
  "confidence": 0.78,
  "reasoning": "This IP exhibits methodical reconnaissance over 28 seconds: robots.txt check → .git/config probe → admin access attempt. Sequential discovery with consistent 13-15s intervals suggests human or scripted methodology. Individually weak signals, but together form clear reconnaissance pattern. While curl is legitimate, this specific sequence indicates deliberate security probing."
}
```

---

## Deployment Examples

### Claude API (Hybrid Mode)

```bash
# 1. Get Claude API key from https://console.anthropic.com/
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# 2. Create secret
oc create secret generic mirror-agent-secrets \
  --from-literal=ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  --from-literal=SHODAN_API_KEY=your-shodan-key \
  -n cyber-riposte

# 3. Deploy with Claude
oc apply -f k8s/agent-deployment-llm-claude.yaml

# 4. Verify LLM is active
oc logs -f deployment/mirror-agent-llm -n cyber-riposte | grep -i "claude"
# Should see: "Hybrid detector initialized with LLM: {'backend': 'claude', ...}"
```

### Hugging Face Local (GPU)

```bash
# 1. Ensure GPU nodes available
oc get nodes -l nvidia.com/gpu.present=true

# 2. Create PVC for model cache (optional but recommended)
cat <<EOF | oc apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: huggingface-model-cache
  namespace: cyber-riposte
spec:
  accessModes:
  - ReadWriteOnce
  resources:
    requests:
      storage: 50Gi
  storageClassName: gp3
EOF

# 3. Deploy with HF local
oc apply -f k8s/agent-deployment-llm-huggingface.yaml

# 4. Watch model loading (takes 30-60s)
oc logs -f deployment/mirror-agent-llm-hf -n cyber-riposte
# Should see: "Loading HuggingFace model meta-llama/Llama-3.1-8B-Instruct on cuda..."
```

### Hugging Face API

```bash
# 1. Get HF token from https://huggingface.co/settings/tokens
export HF_API_TOKEN="hf_your-token-here"

# 2. Create secret
oc create secret generic mirror-agent-secrets \
  --from-literal=HF_API_TOKEN=$HF_API_TOKEN \
  -n cyber-riposte

# 3. Edit deployment to use HF API
oc edit deployment mirror-agent -n cyber-riposte
# Set:
#   LLM_BACKEND: "hybrid"
#   HF_USE_API: "true"
#   HF_MODEL: "meta-llama/Llama-3.1-8B-Instruct"

# 4. Restart
oc rollout restart deployment/mirror-agent -n cyber-riposte
```

---

## Testing

### Test with Fake Event

```bash
# Get agent pod
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')

# Send novel tool event (should trigger LLM)
oc exec -it $AGENT_POD -n cyber-riposte -- python3 -m agent.main <<'EOF'
{"event_type": "alert", "src_ip": "198.51.100.42", "timestamp": "2024-06-15T03:14:07Z", "alert": {"signature": "Suspicious Activity", "category": "Unknown", "severity": 2}, "http": {"http_user_agent": "custom-exploit-tool-v1.0", "http_uri": "/api/v1/users?limit=1000"}}
EOF

# Check logs for LLM reasoning
oc logs $AGENT_POD -n cyber-riposte | grep -A 20 "LLM"
```

### Check LLM Stats

```bash
# View detection statistics
oc exec $AGENT_POD -n cyber-riposte -- python3 <<EOF
from agent.hybrid_detector import HybridDetector
detector = HybridDetector()
# Process some events...
print(detector.get_stats())
EOF
```

---

## Troubleshooting

### Claude API Issues

```bash
# Check API key is set
oc exec deployment/mirror-agent -n cyber-riposte -- env | grep ANTHROPIC

# Test API directly
oc exec -it deployment/mirror-agent -n cyber-riposte -- python3 <<EOF
from anthropic import Anthropic
import os
client = Anthropic(api_key=os.getenv('ANTHROPIC_API_KEY'))
response = client.messages.create(model="claude-sonnet-4-6", max_tokens=100, messages=[{"role": "user", "content": "Hello"}])
print(response.content[0].text)
EOF
```

### Hugging Face GPU Issues

```bash
# Check GPU is allocated
oc describe pod -l app=mirror-agent -n cyber-riposte | grep -A 5 "Limits:"
# Should show: nvidia.com/gpu: 1

# Check CUDA availability
oc exec deployment/mirror-agent-llm-hf -n cyber-riposte -- python3 <<EOF
import torch
print(f"CUDA available: {torch.cuda.is_available()}")
print(f"GPU count: {torch.cuda.device_count()}")
if torch.cuda.is_available():
    print(f"GPU name: {torch.cuda.get_device_name(0)}")
EOF

# If GPU not available, check node
oc get nodes -l nvidia.com/gpu.present=true -o wide
```

### Model Loading Failures

```bash
# Check disk space (models are 5-16GB)
oc exec deployment/mirror-agent -n cyber-riposte -- df -h

# Check model cache
oc exec deployment/mirror-agent -n cyber-riposte -- ls -lh /root/.cache/huggingface/hub/

# Re-download model (delete cache)
oc exec deployment/mirror-agent -n cyber-riposte -- rm -rf /root/.cache/huggingface/
oc rollout restart deployment/mirror-agent -n cyber-riposte
```

---

## FAQ

**Q: Which LLM backend should I use?**  
A: For production with budget: Claude Sonnet (hybrid). For free/offline: Llama 3.1 on GPU. For testing: Rules only.

**Q: How much does Claude cost?**  
A: ~$0.003 per event. With hybrid mode (rules handle 80%), expect $1-5/month for typical deployments.

**Q: Can I use both Claude and Hugging Face?**  
A: Not simultaneously, but you can set `LLM_BACKEND=auto` to try Claude first, fall back to HF if unavailable.

**Q: Does the LLM have access to the internet or can it execute code?**  
A: No. The LLM only receives the event, action pool, and recent context. It returns a JSON decision. The agent code validates and executes it.

**Q: Can the LLM create new actions?**  
A: No. It can only choose from the pre-approved action pool. If it returns an action not in the pool, the agent rejects it.

**Q: What happens if the LLM API is down?**  
A: The hybrid detector falls back to rule-based detection automatically. Events are still processed, just without LLM reasoning.

**Q: Can I use a different model like GPT-4?**  
A: Not currently. The architecture supports Claude and Hugging Face. Adding OpenAI would require a new provider class (similar to `claude_provider.py`).

---

## Next Steps

- **Start simple**: Deploy with rules only, verify it works
- **Add Claude**: Enable hybrid mode with Claude API for better reasoning
- **Or add HF**: Use Llama 3.1 on GPU for free LLM intelligence
- **Monitor costs**: Check Claude API usage dashboard
- **Review reasoning**: Read LLM explanations in audit logs and post-mortems
- **Tune thresholds**: Adjust confidence thresholds in `hybrid_detector.py` based on your false positive rate

The Mirror is now production-ready with or without LLM support! 🎯
