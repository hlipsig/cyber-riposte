# Phase 6: OSINT Resilience Guide

This guide covers Redis caching and rate limiting for OSINT modules to prevent API quota exhaustion and improve performance.

---

## Why OSINT Resilience?

**Phase 1-5** ran OSINT lookups on every incident:
- ❌ API calls repeated for same IP (no caching)
- ❌ Risk of hitting API rate limits (Shodan, CT)
- ❌ Slow lookups (network latency every time)
- ❌ API quota exhaustion (free tier limits)
- ❌ No backpressure when APIs are slow

**Phase 6 (OSINT Resilience)** solves this:
- ✅ Redis caching (7-day TTL, reduces repeated lookups)
- ✅ Rate limiting (token bucket per module)
- ✅ Cache hit/miss statistics
- ✅ Graceful degradation (partial results if rate limited)
- ✅ Evidence still saved even if cached

---

## Quick Start

```bash
# 1. Deploy Redis
oc apply -f k8s/redis-deployment.yaml

# 2. Wait for Redis ready
oc wait --for=condition=ready pod -l app=redis -n cyber-riposte --timeout=300s

# 3. Test Redis connection
REDIS_POD=$(oc get pod -n cyber-riposte -l app=redis -o jsonpath='{.items[0].metadata.name}')
oc exec -it $REDIS_POD -n cyber-riposte -- redis-cli ping
# Should output: PONG

# 4. Deploy/update agent with Redis URL
oc apply -f k8s/agent-deployment-kafka.yaml

# 5. Verify caching working
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "Cache HIT"
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ Mirror Agent (OSINT Execution)                              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Check cache (Redis GET)                                │
│     ├─ HIT  → return cached result (fast!)                 │
│     └─ MISS → continue to step 2                           │
│                                                             │
│  2. Check rate limit (Token bucket)                        │
│     ├─ ALLOWED     → continue to step 3                    │
│     └─ RATE LIMITED → skip, log wait time                  │
│                                                             │
│  3. Execute API call (WHOIS, Shodan, CT, rDNS)            │
│                                                             │
│  4. Store in cache (Redis SETEX with 7-day TTL)           │
│                                                             │
│  5. Return result                                          │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌──────────────────┐
                    │  Redis           │
                    │  (256MB LRU)     │
                    │                  │
                    │  Keys:           │
                    │  osint:whois:*   │
                    │  osint:rdns:*    │
                    │  osint:shodan:*  │
                    │  osint:ct:*      │
                    └──────────────────┘
```

---

## Components

### 1. Redis Cache (agent/osint_cache.py)

**Features**:
- TTL-based expiration (default 7 days)
- Key namespacing by module (osint:whois:*, osint:shodan:*)
- Automatic serialization/deserialization (JSON)
- Cache hit/miss statistics
- LRU eviction policy (maxmemory-policy allkeys-lru)

**Cache key format**:
```
osint:{module}:{target_hash}

Examples:
- osint:whois:a1b2c3d4e5f6
- osint:shodan:1a2b3c4d5e6f
```

**Usage**:
```python
from agent.osint_cache import get_osint_cache

cache = get_osint_cache()

# Try cache first
result = cache.get("whois", "203.0.113.42")
if result:
    return result  # Cache HIT

# Cache MISS - perform lookup
result = expensive_whois_lookup("203.0.113.42")

# Store in cache
cache.set("whois", "203.0.113.42", result, ttl=604800)  # 7 days
```

**Decorator usage**:
```python
from agent.osint_cache import cached_osint

@cached_osint("whois", ttl=604800)
def whois_lookup(ip: str) -> dict:
    # This function automatically cached
    return perform_whois(ip)
```

### 2. Rate Limiter (agent/rate_limiter.py)

**Algorithm**: Token bucket
- Each module has a bucket with N tokens
- Each API call consumes 1 token
- Tokens refill at constant rate

**Limits**:
- **Shodan**: 6 calls per minute (conservative for free tier)
- **WHOIS**: 10 calls per minute (most servers allow ~60/min)
- **rDNS**: 30 calls per minute (local DNS, no strict limit)
- **CT**: 10 calls per minute (crt.sh API)

**Usage**:
```python
from agent.rate_limiter import get_osint_rate_limiter

limiter = get_osint_rate_limiter()

if limiter.allow("shodan"):
    result = shodan_api_call()
else:
    wait = limiter.wait_time("shodan")
    logger.warning(f"Rate limited, wait {wait}s")
```

### 3. Updated Executor (agent/executor.py)

**execute_osint()** now:
1. Checks cache first (Redis GET)
2. Checks rate limit before API call
3. Executes lookup if allowed
4. Stores result in cache
5. Saves evidence to database
6. Returns partial results if rate limited

**Audit log includes**:
- `cached_modules`: Number of cache hits
- `rate_limited_modules`: Number of rate limited modules
- `cache_stats`: Per-module cache status (hit/miss)
- `result`: "success" or "partial" (if rate limited)

---

## Deployment

### 1. Deploy Redis

```bash
# Deploy Redis
oc apply -f k8s/redis-deployment.yaml

# Verify pod running
oc get pods -n cyber-riposte -l app=redis

# Wait for ready
oc wait --for=condition=ready pod -l app=redis -n cyber-riposte --timeout=300s

# Test connection
REDIS_POD=$(oc get pod -n cyber-riposte -l app=redis -o jsonpath='{.items[0].metadata.name}')
oc exec -it $REDIS_POD -n cyber-riposte -- redis-cli ping
# Should output: PONG
```

**What this deploys**:
- Redis 7 Alpine (lightweight image)
- 256MB max memory with LRU eviction
- ConfigMap with redis.conf
- No persistence (cache-only, data lost on restart)
- ClusterIP service (internal only)

### 2. Deploy/Update Agent

Agent deployment already includes `REDIS_URL=redis://redis:6379/0`:

```bash
# Apply updated deployment
oc apply -f k8s/agent-deployment-kafka.yaml

# Verify Redis connection from agent
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec -it $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.osint_cache import get_osint_cache
cache = get_osint_cache()
print('Redis connection:', 'OK' if cache.client else 'FAILED')
"
```

---

## Testing

### Test Cache

```bash
# Generate 2 identical events (same IP)
python3 event-producer-sim.py --kafka localhost:9092 --scenario single --count 1
sleep 5
python3 event-producer-sim.py --kafka localhost:9092 --scenario single --count 1

# Check agent logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "OSINT cache"
# First event: "Cache MISS: whois"
# Second event: "Cache HIT: whois"

# Check cache stats
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.osint_cache import get_osint_cache
cache = get_osint_cache()
print(cache.get_stats())
"
# Output: {'hits': 4, 'misses': 4, 'total': 8, 'hit_rate': 50.0}
```

### Test Rate Limiting

```bash
# Generate many events quickly (trigger rate limit)
for i in {1..20}; do
  python3 event-producer-sim.py --kafka localhost:9092 --scenario single --count 1
  sleep 1
done

# Check agent logs for rate limit warnings
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "rate limited"
# Should see: "OSINT rate limited: shodan (wait: 8.5s)"

# Check rate limit stats
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.rate_limiter import get_osint_rate_limiter
limiter = get_osint_rate_limiter()
print(limiter.get_stats('shodan'))
"
# Output: {'tokens': 3.2, 'rate': 6, 'per': 60, 'wait_time': 0.0}
```

### Check Redis Keys

```bash
# List all cache keys
oc exec $REDIS_POD -n cyber-riposte -- redis-cli KEYS "osint:*"

# Count cache keys by module
oc exec $REDIS_POD -n cyber-riposte -- redis-cli KEYS "osint:whois:*" | wc -l
oc exec $REDIS_POD -n cyber-riposte -- redis-cli KEYS "osint:shodan:*" | wc -l

# Get specific cached result
oc exec $REDIS_POD -n cyber-riposte -- redis-cli GET "osint:whois:a1b2c3d4"

# Check TTL (time to live)
oc exec $REDIS_POD -n cyber-riposte -- redis-cli TTL "osint:whois:a1b2c3d4"
# Output: 604800 (7 days in seconds)
```

---

## Monitoring

### Cache Statistics

```bash
# Cache hit rate from agent
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "cache_stats"

# Redis memory usage
oc exec $REDIS_POD -n cyber-riposte -- redis-cli INFO memory | grep used_memory_human

# Number of keys
oc exec $REDIS_POD -n cyber-riposte -- redis-cli DBSIZE
```

### Rate Limit Status

```bash
# Check rate limit stats from agent logs
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep "rate_limited"

# Rate limit tokens available
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.rate_limiter import get_osint_rate_limiter
limiter = get_osint_rate_limiter()
for module in ['shodan', 'whois', 'rdns', 'ct']:
    print(f'{module}: {limiter.get_stats(module)}')
"
```

### Database Evidence

Even with caching, evidence is still saved to database:

```bash
# Check evidence entries
oc exec postgres-0 -n cyber-riposte -- psql -U mirror_agent -d mirror_audit -c \
  "SELECT incident_id, evidence_type, collected_at
   FROM evidence
   WHERE evidence_type IN ('whois', 'shodan', 'rdns', 'ct')
   ORDER BY collected_at DESC
   LIMIT 10;"
```

---

## Performance Impact

### Before Phase 6 (No Caching)

- **WHOIS lookup**: ~500ms per call
- **Shodan lookup**: ~1-2s per call
- **CT lookup**: ~500ms per call
- **Total OSINT time**: ~3-4s per incident
- **API quota**: 100 Shodan calls → exhausted in 100 incidents

### After Phase 6 (With Caching)

- **Cached lookup**: <5ms (Redis GET)
- **Cache hit rate**: 60-80% (depends on IP diversity)
- **Total OSINT time**: ~1s (3 misses) or ~15ms (all hits)
- **API quota**: 60-80% reduction in Shodan calls

**Example scenario** (1000 incidents):
- **Without caching**: 1000 Shodan calls (quota exhausted at ~500)
- **With caching** (70% hit rate): 300 Shodan calls (quota OK!)

---

## Configuration

### Cache TTL

Default: 7 days (604800 seconds)

**Adjust TTL**:
```python
# In agent/osint_cache.py
cache = OSINTCache(default_ttl=86400)  # 1 day
```

**Or per-module**:
```python
cache.set("whois", ip, result, ttl=3600)  # 1 hour for WHOIS
```

### Rate Limits

Default limits in `agent/rate_limiter.py`:

```python
self.limiters = {
    "shodan": RateLimiter(rate=6, per=60),   # 6 per minute
    "whois": RateLimiter(rate=10, per=60),   # 10 per minute
    "rdns": RateLimiter(rate=30, per=60),    # 30 per minute
    "ct": RateLimiter(rate=10, per=60),      # 10 per minute
}
```

**Adjust for API tier**:
- Shodan paid tier: increase to `rate=100` (1 per second)
- WHOIS dedicated server: increase to `rate=60`

### Redis Memory

Default: 256MB with LRU eviction

**Increase memory** (edit k8s/redis-deployment.yaml):
```yaml
data:
  redis.conf: |
    maxmemory 512mb  # Increase from 256mb
```

**Memory sizing**:
- Average cache entry: ~2KB
- 256MB → ~128,000 entries
- At 70% hit rate, 1000 incidents/day → ~2 weeks of cache

---

## Troubleshooting

### Redis Connection Failed

```bash
# Check Redis pod running
oc get pods -n cyber-riposte -l app=redis

# Check Redis logs
oc logs -l app=redis -n cyber-riposte

# Test connection from agent
AGENT_POD=$(oc get pod -n cyber-riposte -l app=mirror-agent -o jsonpath='{.items[0].metadata.name}')
oc exec -it $AGENT_POD -n cyber-riposte -- nc -zv redis 6379

# Check REDIS_URL env var
oc exec $AGENT_POD -n cyber-riposte -- env | grep REDIS_URL
```

### Cache Not Working

```bash
# Check agent logs for cache errors
oc logs deployment/mirror-agent-kafka -n cyber-riposte | grep -i "cache"

# Check Redis client installed
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "import redis; print('Redis client OK')"

# Manually test cache
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.osint_cache import get_osint_cache
cache = get_osint_cache()
cache.set('test', '127.0.0.1', {'test': 'data'})
print(cache.get('test', '127.0.0.1'))
"
```

### High Cache Miss Rate

```bash
# Check hit rate
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.osint_cache import get_osint_cache
print(get_osint_cache().get_stats())
"

# Common causes:
# 1. High IP diversity (many unique IPs)
# 2. Cache recently flushed
# 3. TTL too short (expired entries)
# 4. Redis memory full (LRU eviction)

# Check Redis memory
oc exec $REDIS_POD -n cyber-riposte -- redis-cli INFO memory
```

### Rate Limiting Too Aggressive

If legitimate incidents are being rate limited:

```bash
# Check current limits
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.rate_limiter import get_osint_rate_limiter
limiter = get_osint_rate_limiter()
print('Shodan:', limiter.get_stats('shodan'))
"

# Increase limits (edit agent/rate_limiter.py):
"shodan": RateLimiter(rate=12, per=60),  # Increase from 6 to 12
```

---

## Cleanup

### Flush Cache

```bash
# Flush all OSINT cache keys
oc exec $REDIS_POD -n cyber-riposte -- redis-cli --scan --pattern "osint:*" | xargs -L 1000 redis-cli DEL

# Or via agent
oc exec $AGENT_POD -n cyber-riposte -- python3 -c "
from agent.osint_cache import get_osint_cache
get_osint_cache().flush_all()
"
```

### Reset Rate Limits

```bash
# Rate limits are in-memory (per agent pod)
# Reset by restarting agent
oc rollout restart deployment/mirror-agent-kafka -n cyber-riposte
```

---

## Next Steps

After Phase 6 is working:

- **Phase 7**: Observability (Prometheus metrics for cache hit rate, rate limit status)
- **Phase 8**: GitHub integration (include cache stats in incident issues)
- **Phase 9**: Hot-reload (reload rate limits without restart)

---

## Summary

**Phase 6 Complete** when:

✅ Redis deployed and running  
✅ Agent connects to Redis successfully  
✅ Cache HIT logs appearing  
✅ Cache stats showing > 0% hit rate  
✅ Rate limiting working (wait_time logged when limited)  
✅ Evidence still saved to database (even if cached)  
✅ Partial results logged when rate limited  
✅ Redis memory < 80% used

The Mirror now has **resilient OSINT** with caching and rate limiting! 🚀
