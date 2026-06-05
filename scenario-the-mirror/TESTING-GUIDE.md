# Phase 10: Testing & CI/CD Guide

This guide covers unit tests, integration tests, and CI/CD pipeline for The Mirror.

---

## Why Testing?

**Phase 1-9** had no automated tests:
- ❌ Manual testing only
- ❌ Regressions not caught
- ❌ No confidence in changes
- ❌ Hard to refactor safely
- ❌ No CI/CD automation

**Phase 10 (Testing & CI/CD)** solves this:
- ✅ Unit tests for core logic
- ✅ Integration tests for components
- ✅ GitHub Actions CI pipeline
- ✅ Automated testing on every PR
- ✅ Code coverage tracking
- ✅ Container image scanning
- ✅ Kubernetes manifest validation

---

## Quick Start

```bash
# 1. Install test dependencies
cd ~/REPOS/cyber-riposte/scenario-the-mirror
pip install pytest pytest-cov pytest-mock

# 2. Run all tests
pytest tests/ -v

# 3. Run with coverage
pytest tests/ --cov=agent --cov-report=term --cov-report=html

# 4. View coverage report
open htmlcov/index.html
```

---

## Test Structure

```
scenario-the-mirror/
├── tests/
│   ├── __init__.py
│   ├── test_detector.py         # Unit: Detection logic
│   ├── test_osint_cache.py      # Unit: Redis caching
│   ├── test_rate_limiter.py     # Unit: Rate limiting
│   ├── test_config_watcher.py   # Unit: Hot-reload (future)
│   └── test_integration.py      # Integration tests (future)
├── pytest.ini                    # Pytest configuration
└── .github/
    └── workflows/
        └── mirror-ci.yml         # CI/CD pipeline
```

---

## Unit Tests

### test_detector.py

Tests reconnaissance detection logic:
- IDS alert detection
- Suspicious user agent detection
- Multiple signal detection
- Benign event handling
- Confidence calculation

**Run**:
```bash
pytest tests/test_detector.py -v
```

**Coverage**:
- ✅ `detect_recon()` function
- ✅ Signal extraction
- ✅ Confidence scoring
- ✅ Edge cases (missing fields)

### test_osint_cache.py

Tests Redis caching functionality:
- Cache hit/miss
- Data storage and retrieval
- TTL handling
- Statistics tracking
- Graceful degradation (no Redis)

**Run**:
```bash
pytest tests/test_osint_cache.py -v
```

**Mocking**: Uses `unittest.mock` to mock Redis client (no real Redis needed).

### test_rate_limiter.py

Tests token bucket rate limiter:
- Token consumption
- Rate limit enforcement
- Token refill over time
- Wait time calculation
- Per-module limits (OSINT)

**Run**:
```bash
pytest tests/test_rate_limiter.py -v
```

---

## Running Tests

### All Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=agent --cov-report=term

# Run with HTML coverage report
pytest tests/ --cov=agent --cov-report=html
open htmlcov/index.html
```

### Specific Tests

```bash
# Run single test file
pytest tests/test_detector.py -v

# Run single test class
pytest tests/test_detector.py::TestDetectRecon -v

# Run single test method
pytest tests/test_detector.py::TestDetectRecon::test_ids_alert_detection -v
```

### By Markers

```bash
# Run only unit tests (fast)
pytest tests/ -m unit -v

# Run only integration tests
pytest tests/ -m integration -v

# Skip slow tests
pytest tests/ -m "not slow" -v
```

### Watch Mode

```bash
# Install pytest-watch
pip install pytest-watch

# Run tests on file changes
ptw tests/ agent/ -- -v
```

---

## CI/CD Pipeline

### GitHub Actions Workflow

**File**: `.github/workflows/mirror-ci.yml`

**Triggers**:
- Push to `main` branch (changes to `scenario-the-mirror/*`)
- Pull requests to `main` branch

**Jobs**:

#### 1. Test Job
- Install Python 3.11
- Install dependencies
- Run pytest with coverage
- Upload coverage to Codecov

#### 2. Lint Job
- Run flake8 (syntax errors, undefined names)
- Check code formatting with black
- Check import sorting with isort

#### 3. Build Job
- Build container image with Docker Buildx
- Scan image with Trivy (security vulnerabilities)
- Upload security results to GitHub Security

#### 4. Validate Manifests Job
- Install kubeval
- Validate all Kubernetes YAML manifests

### Viewing CI Results

```bash
# On GitHub:
# 1. Go to Actions tab
# 2. Click on workflow run
# 3. View job results

# Locally check what CI will do:
cd scenario-the-mirror

# Run tests
pytest tests/ -v --cov=agent

# Run linting
flake8 agent/ --select=E9,F63,F7,F82
black --check agent/
isort --check-only agent/

# Build image
docker build -t mirror-agent:test .

# Validate manifests
kubeval k8s/*.yaml
```

---

## Code Coverage

### Current Coverage

**Target**: 80% coverage

**Coverage by module**:
- `agent/detector.py`: ~90% (unit tests)
- `agent/osint_cache.py`: ~85% (unit tests)
- `agent/rate_limiter.py`: ~90% (unit tests)
- `agent/config_watcher.py`: ~0% (no tests yet)
- `agent/executor.py`: ~30% (partial, needs integration tests)
- `agent/main.py`: ~20% (partial, needs integration tests)

### Viewing Coverage

```bash
# Generate HTML report
pytest tests/ --cov=agent --cov-report=html

# Open in browser
open htmlcov/index.html

# Terminal report with line numbers
pytest tests/ --cov=agent --cov-report=term-missing
```

### Coverage on GitHub

Coverage is uploaded to Codecov on every CI run:
- Go to: https://codecov.io/gh/hlipsig/cyber-riposte
- View coverage trends over time
- See which files need more tests

---

## Integration Tests (Future)

### test_integration.py (To Be Created)

Tests that require external dependencies:

```python
# Example integration tests

@pytest.mark.integration
def test_redis_cache_integration():
    """Test with real Redis instance."""
    # Requires: docker run -d -p 6379:6379 redis:7-alpine
    cache = OSINTCache(redis_url="redis://localhost:6379/0")
    cache.set("test", "1.2.3.4", {"data": "test"})
    result = cache.get("test", "1.2.3.4")
    assert result["data"] == "test"

@pytest.mark.integration
def test_database_audit_log():
    """Test with real PostgreSQL."""
    # Requires: PostgreSQL running
    from agent.db import get_db_manager
    db = get_db_manager()
    audit_id = db.log_audit_entry(...)
    assert audit_id is not None

@pytest.mark.integration
def test_kafka_consumer():
    """Test Kafka consumer."""
    # Requires: Kafka running
    from agent.kafka_consumer import MirrorKafkaConsumer
    consumer = MirrorKafkaConsumer()
    assert consumer.connect()
```

**Running integration tests**:
```bash
# Start dependencies with Docker Compose
docker-compose -f tests/docker-compose.test.yml up -d

# Run integration tests
pytest tests/ -m integration -v

# Cleanup
docker-compose -f tests/docker-compose.test.yml down
```

---

## End-to-End Tests (Future)

### test_e2e.py (To Be Created)

Full stack tests:

```python
@pytest.mark.e2e
def test_full_incident_workflow():
    """Test complete incident detection and response."""
    # 1. Start agent
    # 2. Publish fake event to Kafka
    # 3. Verify detection
    # 4. Verify VirtualService created
    # 5. Verify OSINT collected
    # 6. Verify audit log written
    # 7. Verify evidence in database
```

---

## Test Data

### Fixtures

Create test fixtures for reusable data:

```python
# tests/conftest.py

@pytest.fixture
def sample_ids_alert():
    """Sample IDS alert event."""
    return {
        "event_type": "alert",
        "src_ip": "203.0.113.42",
        "alert": {
            "category": "Attempted Recon",
            "signature": "Nmap scan detected",
        },
        "timestamp": "2024-06-15T03:14:07.123Z",
    }

@pytest.fixture
def mock_action_pool(tmp_path):
    """Mock action pool YAML file."""
    pool_file = tmp_path / "action-pool.yaml"
    pool_file.write_text("""
global:
  allowlisted_ips:
    - "10.0.0.0/8"

actions:
  - id: "redirect-to-honeypot"
    name: "Redirect to honeypot"
    tier: 1
    auto_execute: true
""")
    return str(pool_file)
```

---

## Continuous Integration

### On Every Push to Main

1. **Tests run automatically**
2. **Lint checks run**
3. **Image builds**
4. **Security scans run**
5. **Manifests validated**

### On Every Pull Request

Same checks run + PR status checks:
- ✅ All tests must pass
- ✅ No critical security issues
- ✅ Code coverage maintained

### Merge Requirements

Configure branch protection on GitHub:
- ✅ Require status checks to pass
- ✅ Require review approval
- ✅ Require up-to-date branch

---

## Local Development Workflow

### Before Committing

```bash
# 1. Run tests
pytest tests/ -v

# 2. Check coverage
pytest tests/ --cov=agent --cov-report=term

# 3. Run linting
flake8 agent/
black agent/
isort agent/

# 4. Build image
docker build -t mirror-agent:dev .

# 5. Test image
docker run --rm mirror-agent:dev python3 -c "import agent; print('OK')"
```

### Pre-Commit Hooks

Install pre-commit hooks to run checks automatically:

```bash
# Install pre-commit
pip install pre-commit

# Create .pre-commit-config.yaml
cat > .pre-commit-config.yaml <<EOF
repos:
  - repo: https://github.com/psf/black
    rev: 23.12.0
    hooks:
      - id: black
        args: [--line-length=127]
  
  - repo: https://github.com/PyCQA/flake8
    rev: 7.0.0
    hooks:
      - id: flake8
        args: [--max-line-length=127]
  
  - repo: https://github.com/PyCQA/isort
    rev: 5.13.0
    hooks:
      - id: isort
EOF

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

---

## Troubleshooting Tests

### Import Errors

```bash
# Make sure you're in the right directory
cd ~/REPOS/cyber-riposte/scenario-the-mirror

# Install in editable mode
pip install -e .

# Or set PYTHONPATH
export PYTHONPATH=$PWD:$PYTHONPATH
pytest tests/
```

### Redis Tests Failing

```bash
# Redis tests use mocks, shouldn't need real Redis
# If seeing connection errors, check mock setup

# For integration tests, start Redis
docker run -d -p 6379:6379 --name test-redis redis:7-alpine

# Cleanup
docker stop test-redis && docker rm test-redis
```

### Slow Tests

```bash
# Mark slow tests
@pytest.mark.slow
def test_slow_operation():
    time.sleep(10)

# Skip slow tests
pytest tests/ -m "not slow" -v
```

---

## Next Steps

Future test additions:
- **Integration tests**: Kafka, PostgreSQL, Redis
- **E2E tests**: Full incident workflow
- **Performance tests**: Load testing with many events
- **Contract tests**: API compatibility
- **Mutation tests**: Test quality of tests

---

## Summary

**Phase 10 Complete** when:

✅ Unit tests written (detector, cache, rate limiter)  
✅ Pytest configuration set up  
✅ GitHub Actions CI/CD pipeline created  
✅ Tests run on every PR/push  
✅ Code coverage tracked  
✅ Container image security scanning  
✅ Kubernetes manifest validation  
✅ Documentation complete

The Mirror now has **automated testing and CI/CD**! 🧪
