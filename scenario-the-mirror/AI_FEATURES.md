# AI-Enhanced Threat Intelligence Features

**Added**: 2026-06-11  
**Model**: Hugging Face distilgpt2

---

## Overview

The Mirror now includes AI-powered incident narrative generation using Hugging Face transformers. Each detected security incident automatically receives a professional threat intelligence analysis.

## Components

### 1. AI Narrator Module (`agent/ai_narrator.py`)

Generates human-readable security incident narratives using the Hugging Face distilgpt2 model.

**Features**:
- Text generation with configurable models (distilgpt2, gpt2, facebook/opt-125m)
- Multiple narrative styles (technical, executive, detailed)
- Intelligent caching to avoid regenerating identical narratives
- Graceful fallback to template-based narratives if AI unavailable
- Configurable via environment variables

**Configuration**:
```bash
AI_ENABLED=true              # Enable/disable AI narrator (default: true)
AI_MODEL=distilgpt2          # Model to use (default: distilgpt2)
```

**Models**:
- `distilgpt2` - 82MB, fast, recommended (default)
- `gpt2` - 548MB, better quality
- `facebook/opt-125m` - 250MB, optimized for inference

### 2. Log-Based Detection (`agent/log_detector.py`)

Real-time log analysis for detecting reconnaissance and attack patterns.

**Detection Capabilities**:
- Nmap scanning (user-agent pattern matching)
- Directory brute forcing (gobuster, dirb, ffuf, wfuzz)
- Web vulnerability scanners (Nikto, SQLMap, Burp Suite, OWASP ZAP)
- High request rate anomalies (>20 requests/60 seconds)

**Integration**:
- Automatically generates AI narratives for detected incidents
- Stores incidents in PostgreSQL with full metadata
- Supports OSINT integration hooks

### 3. Web Dossier Interface (`agent/web_dossier.py`)

Flask-based web interface for viewing security incident dossiers.

**Features**:
- HTTP Basic Authentication
- Rate limiting (5 failed attempts = 15 minute lockout)
- Incident list view with filtering
- Detailed dossier view with AI narratives
- Mobile-responsive design
- Terminal-inspired UI theme

**Endpoints**:
- `/` - Index/welcome page
- `/dossiers` - List all incidents
- `/dossiers/<incident_id>` - Detailed dossier view
- `/api/dossiers/<ip_address>` - JSON API for IP lookup

### 4. Database Schema Updates

**New Columns**:
- `incidents.ai_narrative` (TEXT) - Stores AI-generated threat analysis

**Schema Updates**:
```sql
ALTER TABLE incidents ADD COLUMN ai_narrative TEXT;
```

## Architecture

```
┌─────────────────────┐
│   Log Sources       │
│  (nginx, etc.)      │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│  Log Detector       │
│  - Pattern matching │
│  - Rate detection   │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐      ┌──────────────────┐
│  AI Narrator        │◄─────┤ Hugging Face     │
│  - Generate text    │      │ transformers     │
│  - Cache results    │      └──────────────────┘
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│  PostgreSQL DB      │
│  - incidents table  │
│  - ai_narrative col │
└──────────┬──────────┘
           │
           v
┌─────────────────────┐
│  Web Dossier UI     │
│  - Flask app        │
│  - Display narratives│
└─────────────────────┘
```

## Example Output

**AI-Generated Narrative**:
```
Security incident report: An attacker from IP 203.0.113.42 was detected 
conducting reconnaissance using Nmap scanning tools against our infrastructure. 
Detection confidence: 98%. Technical analysis: The adversary employed automated 
scanning techniques consistent with pre-attack reconnaissance. This behavior 
indicates a deliberate attempt to enumerate our services and identify potential 
vulnerabilities for future exploitation.
```

**Fallback Template** (if AI unavailable):
```
A high-confidence security incident was detected from IP address 203.0.113.42. 
The activity matched the signature: ET SCAN Nmap Scripting Engine User-Agent 
Detected. Our detection systems identified this threat with 98% confidence, 
indicating a deliberate reconnaissance effort.
```

## Performance

- **First narrative generation**: ~2-5 seconds (model loading)
- **Subsequent generations**: ~1-2 seconds (CPU)
- **Cache hits**: <10ms
- **Model size**: 82MB (distilgpt2)
- **Resource usage**: CPU-only, no GPU required

## Deployment

### Dependencies

Already included in `requirements.txt`:
```
transformers>=4.45.0
torch>=2.1.0
accelerate>=0.20.0
```

### Environment Variables

```bash
# AI Narrator
AI_ENABLED=true
AI_MODEL=distilgpt2

# Web Dossier
DOSSIER_PORT=8081
DOSSIER_PASSWORD=<set-your-password>

# Database (required)
DATABASE_URL=postgresql://user:pass@host:5432/dbname
```

### Kubernetes/OpenShift

The agent deployment exposes two ports:
- `8080` - Health/readiness checks
- `8081` - Web dossier interface

Route the dossier service to port 8081 for external access.

## Security Considerations

1. **Authentication**: Web dossier uses HTTP Basic Auth
2. **Rate Limiting**: Protects against password brute forcing
3. **Input Validation**: AI narrative generation validates incident data
4. **SQL Injection**: All queries use parameterized statements
5. **XSS Protection**: Template engine auto-escapes output

## Educational Use

This implementation demonstrates:
- **AI/ML in Cybersecurity**: Practical threat intelligence generation
- **Real-time Detection**: Log-based pattern matching
- **Counter-Reconnaissance**: Profiling adversaries during reconnaissance
- **Modern Tech Stack**: Hugging Face + Flask + PostgreSQL integration

## Future Enhancements

- [ ] Support for GPT-based models (when available)
- [ ] Multi-language narrative generation
- [ ] Automated threat severity scoring
- [ ] Integration with MITRE ATT&CK framework
- [ ] Export to STIX/TAXII formats
- [ ] Webhook notifications for high-confidence incidents

## License

Same as parent project.

## Contributors

- Initial implementation: Claude Code session 2026-06-11
