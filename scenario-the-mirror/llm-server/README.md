# Local LLM Server - Crash-Free AI for The Mirror

**Problem**: Downloading large models (Llama-3.1-8B) at runtime crashes the Mirror agent.

**Solution**: Pre-built lightweight LLM server with TinyLlama-1.1B-Chat.

## Features

- **No Runtime Downloads**: Model pre-downloaded at build time
- **Lightweight**: TinyLlama-1.1B (only 1.1B parameters)
- **CPU-Optimized**: Runs efficiently on CPU without GPU
- **Fast Inference**: ~500ms-2s per generation
- **Crash-Free**: Tested stable on OpenShift

## Model Specs

- **Model**: TinyLlama/TinyLlama-1.1B-Chat-v1.0
- **Size**: ~2.2GB on disk
- **Parameters**: 1.1 billion
- **Context**: 2048 tokens
- **Performance**: 10-20 tokens/sec on CPU

## API Endpoints

### Health Check
```bash
GET /health

Response:
{
  "status": "healthy",
  "model": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
  "device": "cpu"
}
```

### Model Info
```bash
GET /info

Response:
{
  "model": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
  "device": "cpu",
  "max_tokens": 512,
  "ready": true
}
```

### Generate Completion
```bash
POST /generate
Content-Type: application/json

{
  "prompt": "Analyze this security alert...",
  "max_tokens": 512,
  "temperature": 0.3
}

Response:
{
  "text": "This appears to be...",
  "model": "TinyLlama/...",
  "timestamp": "2026-06-13T..."
}
```

### Chat Completion
```bash
POST /chat
Content-Type: application/json

{
  "messages": [
    {"role": "system", "content": "You are a security analyst"},
    {"role": "user", "content": "Is this an attack?"}
  ],
  "max_tokens": 512,
  "temperature": 0.3
}

Response:
{
  "text": "Yes, this shows signs of...",
  "model": "TinyLlama/...",
  "timestamp": "..."
}
```

### Security Event Evaluation (Mirror-specific)
```bash
POST /evaluate
Content-Type: application/json

{
  "event": {
    "src_ip": "1.2.3.4",
    "alert": {"signature": "ET SCAN Nmap", "severity": 1}
  },
  "action_pool": [
    {"id": "redirect-to-honeypot"},
    {"id": "temp-block"}
  ]
}

Response:
{
  "action": "redirect-to-honeypot",
  "reasoning": "High-severity port scan detected",
  "confidence": 0.85
}
```

## Building & Deploying

### Build Container Image
```bash
cd llm-server

# Build locally
docker build -t llm-server:latest .

# Build on OpenShift
oc new-build --binary --name=llm-server -l app=llm-server
oc start-build llm-server --from-dir=. --follow
```

**Note**: Build takes ~5-10 minutes (downloads model at build time).

### Deploy to Cluster
```bash
# Deploy LLM server
oc apply -f k8s/llm-server-deployment.yaml

# Wait for model to load
oc wait --for=condition=Ready pod -l app=llm-server --timeout=300s

# Check logs
oc logs -f deployment/llm-server

# Test health
oc exec -it deployment/mirror-agent -- curl http://llm-server:8000/health
```

### Configure Mirror Agent
```yaml
env:
- name: LLM_BACKEND
  value: "local-server"  # Use local server instead of huggingface
- name: LLM_SERVER_URL
  value: "http://llm-server:8000"
```

Or use auto-detection (tries local-server first):
```yaml
env:
- name: LLM_BACKEND
  value: "auto"
```

## Performance

**Startup Time**:
- Container start: ~10s
- Model load: ~30-60s
- Total ready time: ~60-90s

**Inference Time** (CPU):
- Simple query: ~500ms
- Security evaluation: ~1-2s
- Max throughput: ~2-3 requests/sec

**Resource Usage**:
- RAM: 2-3Gi (model + inference)
- CPU: 500m baseline, 1-2 CPU during inference
- Disk: 2.5Gi (model weights)

## Comparison: TinyLlama vs Llama-3.1-8B

| Metric | TinyLlama-1.1B | Llama-3.1-8B |
|--------|----------------|--------------|
| Parameters | 1.1B | 8B |
| Model Size | 2.2GB | 16GB |
| RAM Required | 2-3Gi | 16-24Gi |
| CPU Inference | Fast (~1s) | Slow (~10s) |
| Runtime Download | No (pre-built) | Yes (crashes) |
| **Status** | ✅ Works | ❌ Crashes |

## Troubleshooting

### Server not starting
```bash
# Check pod events
oc describe pod -l app=llm-server

# Check logs
oc logs deployment/llm-server

# Common issue: Memory limit too low
# Solution: Increase memory to 4Gi in deployment
```

### Model loading timeout
```bash
# Startup probe allows 2 minutes
# If still failing, increase failureThreshold in deployment:
startupProbe:
  failureThreshold: 18  # 3 minutes
```

### Slow inference
```bash
# Expected on CPU: 1-2s per query
# To improve:
# 1. Add more CPU (increase limits to 2-4 CPU)
# 2. Use GPU node (change device to cuda)
# 3. Switch to smaller model (e.g., TinyLlama-1.1B already smallest)
```

### Connection refused from Mirror agent
```bash
# Check service exists
oc get svc llm-server

# Test from agent pod
oc exec -it deployment/mirror-agent -- curl http://llm-server:8000/health

# Check NetworkPolicies
oc get networkpolicy
```

## Alternative Models

If TinyLlama quality is insufficient, try these lightweight alternatives:

**Phi-2** (2.7B parameters, 5.5GB):
```dockerfile
RUN python3 -c "from transformers import AutoTokenizer, AutoModelForCausalLM; \
    model_id = 'microsoft/phi-2'; \
    tokenizer = AutoTokenizer.from_pretrained(model_id); \
    model = AutoModelForCausalLM.from_pretrained(model_id)"
```

**Falcon-RW-1B** (1B parameters, 2GB):
```dockerfile
RUN python3 -c "from transformers import AutoTokenizer, AutoModelForCausalLM; \
    model_id = 'tiiuae/falcon-rw-1b'; \
    tokenizer = AutoTokenizer.from_pretrained(model_id); \
    model = AutoModelForCausalLM.from_pretrained(model_id)"
```

## Development

### Local Testing
```bash
cd llm-server

# Install dependencies
pip install -r requirements.txt

# Download model
python3 -c "from transformers import AutoTokenizer, AutoModelForCausalLM; \
    AutoTokenizer.from_pretrained('TinyLlama/TinyLlama-1.1B-Chat-v1.0'); \
    AutoModelForCausalLM.from_pretrained('TinyLlama/TinyLlama-1.1B-Chat-v1.0')"

# Run server
python3 llm_server.py

# Test in another terminal
curl http://localhost:8000/health
curl -X POST http://localhost:8000/generate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello", "max_tokens": 50}'
```

### Testing with Mirror Agent (Local)
```python
from agent.llm.local_server_provider import LocalServerProvider

provider = LocalServerProvider(server_url="http://localhost:8000")

if provider.is_available():
    print("✅ Server available:", provider.get_model_info())
    
    event = {
        "src_ip": "1.2.3.4",
        "alert": {
            "signature": "ET SCAN Nmap",
            "severity": 1
        }
    }
    
    response = provider.evaluate_event(event, [{"id": "redirect-to-honeypot"}])
    print("Response:", response.action, response.confidence)
else:
    print("❌ Server not available")
```

## Production Recommendations

1. **Always use `local-server` backend in production** (not `huggingface`)
2. **Pre-build image** with model included (don't download at runtime)
3. **Set resource limits**: 2-4Gi RAM, 1-2 CPU
4. **Monitor inference time**: Alert if >5s per request
5. **Health checks**: Startup probe with 2-3 minute timeout
6. **Horizontal scaling**: Can run multiple replicas with load balancer

## Roadmap

- [ ] Add vLLM for faster inference
- [ ] Support model selection via env var
- [ ] Implement request batching
- [ ] Add Prometheus metrics
- [ ] GPU support for faster inference
- [ ] Model caching/warm start optimization
