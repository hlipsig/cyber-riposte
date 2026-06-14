# Lightweight LLM Server for The Mirror
# Uses TinyLlama-1.1B for fast CPU inference without crashing

FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir \
    flask==3.0.0 \
    transformers==4.45.0 \
    torch==2.1.0 \
    accelerate==0.24.0 \
    sentencepiece==0.1.99

# Pre-download model at build time (avoids runtime download crash)
# Default: DistilGPT-2 (82M params, ~330MB) - Ultra lightweight, fast on CPU
# Alternative: TinyLlama-1.1B-Chat-v1.0 (1.1B params, ~2.2GB) - Better quality
ARG MODEL_ID=distilgpt2
RUN python3 -c "from transformers import AutoTokenizer, AutoModelForCausalLM; \
    import os; \
    model_id = os.getenv('MODEL_ID', 'distilgpt2'); \
    print(f'Downloading {model_id}...'); \
    tokenizer = AutoTokenizer.from_pretrained(model_id); \
    model = AutoModelForCausalLM.from_pretrained(model_id); \
    print(f'Model downloaded successfully: {model_id}')"

# Copy server code
COPY llm_server.py /app/

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Run server
CMD ["python3", "llm_server.py"]
