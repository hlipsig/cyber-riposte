#!/usr/bin/env python3
"""
Lightweight LLM Server for The Mirror

Serves TinyLlama-1.1B-Chat model via HTTP API.
Optimized for CPU inference without crashes.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Dict, Optional

from flask import Flask, request, jsonify
from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# Flask app
app = Flask(__name__)

# Global model and tokenizer
# Default: DistilGPT-2 (82M params, super fast, no crashes)
MODEL_ID = os.getenv("LLM_MODEL", "distilgpt2")
DEVICE = os.getenv("LLM_DEVICE", "cpu")
MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "256"))  # DistilGPT-2 is better with shorter responses

model = None
tokenizer = None
gen_pipeline = None


def load_model():
    """Load model at startup."""
    global model, tokenizer, gen_pipeline

    logger.info(f"Loading model: {MODEL_ID} on {DEVICE}")

    try:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_ID,
            torch_dtype="auto",
            device_map=DEVICE
        )

        gen_pipeline = pipeline(
            "text-generation",
            model=model,
            tokenizer=tokenizer,
            device=DEVICE
        )

        logger.info(f"✅ Model loaded successfully: {MODEL_ID}")
        return True

    except Exception as e:
        logger.error(f"Failed to load model: {e}")
        return False


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    if model is None or tokenizer is None:
        return jsonify({
            "status": "unhealthy",
            "reason": "model not loaded"
        }), 503

    return jsonify({
        "status": "healthy",
        "model": MODEL_ID,
        "device": DEVICE
    }), 200


@app.route('/info', methods=['GET'])
def info():
    """Model information endpoint."""
    return jsonify({
        "model": MODEL_ID,
        "device": DEVICE,
        "max_tokens": MAX_TOKENS,
        "ready": model is not None
    })


@app.route('/generate', methods=['POST'])
def generate():
    """
    Generate text completion.

    Request body:
    {
      "prompt": "...",
      "max_tokens": 512,
      "temperature": 0.3
    }

    Response:
    {
      "text": "...",
      "model": "TinyLlama/...",
      "timestamp": "2026-06-13T..."
    }
    """
    if gen_pipeline is None:
        return jsonify({
            "error": "Model not loaded"
        }), 503

    try:
        data = request.get_json()

        if not data or "prompt" not in data:
            return jsonify({
                "error": "Missing 'prompt' in request body"
            }), 400

        prompt = data["prompt"]
        max_new_tokens = data.get("max_tokens", MAX_TOKENS)
        temperature = data.get("temperature", 0.3)

        logger.info(f"Generating response (max_tokens={max_new_tokens}, temp={temperature})")

        # Generate
        outputs = gen_pipeline(
            prompt,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            do_sample=True,
            top_p=0.9,
            return_full_text=False
        )

        generated_text = outputs[0]['generated_text']

        logger.info(f"Generated {len(generated_text)} chars")

        return jsonify({
            "text": generated_text,
            "model": MODEL_ID,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Generation error: {e}", exc_info=True)
        return jsonify({
            "error": str(e)
        }), 500


@app.route('/chat', methods=['POST'])
def chat():
    """
    Chat completion endpoint (compatible with OpenAI-style API).

    Request body:
    {
      "messages": [
        {"role": "system", "content": "You are a cybersecurity agent"},
        {"role": "user", "content": "Analyze this alert"}
      ],
      "max_tokens": 512,
      "temperature": 0.3
    }

    Response:
    {
      "text": "...",
      "model": "TinyLlama/...",
      "timestamp": "..."
    }
    """
    if gen_pipeline is None or tokenizer is None:
        return jsonify({
            "error": "Model not loaded"
        }), 503

    try:
        data = request.get_json()

        if not data or "messages" not in data:
            return jsonify({
                "error": "Missing 'messages' in request body"
            }), 400

        messages = data["messages"]
        max_new_tokens = data.get("max_tokens", MAX_TOKENS)
        temperature = data.get("temperature", 0.3)

        # Apply chat template if available
        if hasattr(tokenizer, 'apply_chat_template'):
            prompt = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        else:
            # Fallback: simple concatenation
            prompt = "\n\n".join([
                f"{msg['role']}: {msg['content']}"
                for msg in messages
            ])

        logger.info(f"Chat completion (messages={len(messages)}, max_tokens={max_new_tokens})")

        # Generate
        outputs = gen_pipeline(
            prompt,
            max_new_tokens=max_new_tokens,
            temperature=temperature,
            do_sample=True,
            top_p=0.9,
            return_full_text=False
        )

        generated_text = outputs[0]['generated_text']

        logger.info(f"Generated {len(generated_text)} chars")

        return jsonify({
            "text": generated_text,
            "model": MODEL_ID,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        return jsonify({
            "error": str(e)
        }), 500


@app.route('/evaluate', methods=['POST'])
def evaluate():
    """
    Security event evaluation endpoint (Mirror-specific).

    Request body:
    {
      "event": {...},  # Suricata EVE event
      "action_pool": [...],  # Available actions
      "recent_context": [...]  # Recent events (optional)
    }

    Response:
    {
      "action": "redirect-to-honeypot",
      "reasoning": "...",
      "confidence": 0.85
    }
    """
    if gen_pipeline is None or tokenizer is None:
        return jsonify({
            "error": "Model not loaded"
        }), 503

    try:
        data = request.get_json()

        if not data or "event" not in data:
            return jsonify({
                "error": "Missing 'event' in request body"
            }), 400

        event = data["event"]
        action_pool = data.get("action_pool", [])

        # Build evaluation prompt
        prompt = _build_evaluation_prompt(event, action_pool)

        # Format as chat
        messages = [
            {
                "role": "system",
                "content": "You are a cybersecurity defense agent. Respond only with valid JSON."
            },
            {
                "role": "user",
                "content": prompt
            }
        ]

        # Apply chat template
        if hasattr(tokenizer, 'apply_chat_template'):
            formatted_prompt = tokenizer.apply_chat_template(
                messages,
                tokenize=False,
                add_generation_prompt=True
            )
        else:
            formatted_prompt = f"system: {messages[0]['content']}\n\nuser: {messages[1]['content']}"

        # Generate
        outputs = gen_pipeline(
            formatted_prompt,
            max_new_tokens=512,
            temperature=0.3,
            do_sample=True,
            top_p=0.9,
            return_full_text=False
        )

        response_text = outputs[0]['generated_text']

        # Parse JSON response
        decision = _parse_json_response(response_text)

        if not decision:
            return jsonify({
                "error": "Failed to parse model response",
                "raw_response": response_text
            }), 500

        return jsonify(decision)

    except Exception as e:
        logger.error(f"Evaluation error: {e}", exc_info=True)
        return jsonify({
            "error": str(e)
        }), 500


def _build_evaluation_prompt(event: Dict, action_pool: list) -> str:
    """Build evaluation prompt for security event."""
    return f"""Analyze this security event and decide on an action.

Event:
- Source IP: {event.get('src_ip')}
- Alert: {event.get('alert', {}).get('signature', 'Unknown')}
- Category: {event.get('alert', {}).get('category', 'Unknown')}
- Severity: {event.get('alert', {}).get('severity', 3)}

Available Actions:
{json.dumps([a.get('id') for a in action_pool], indent=2)}

Respond with JSON only:
{{
  "action": "action-id",
  "reasoning": "why this action",
  "confidence": 0.0-1.0
}}
"""


def _parse_json_response(response_text: str) -> Optional[Dict]:
    """Parse JSON from model response."""
    try:
        # Extract JSON from markdown or mixed content
        if "```json" in response_text:
            start = response_text.find("```json") + 7
            end = response_text.find("```", start)
            response_text = response_text[start:end].strip()
        elif "{" in response_text:
            start = response_text.find("{")
            end = response_text.rfind("}") + 1
            response_text = response_text[start:end]

        decision = json.loads(response_text)

        # Validate
        if "action" not in decision:
            decision["action"] = "no_action"
        if "reasoning" not in decision:
            decision["reasoning"] = "No reasoning provided"
        if "confidence" not in decision:
            decision["confidence"] = 0.5

        return decision

    except Exception as e:
        logger.error(f"JSON parse error: {e}")
        return None


def main():
    """Main entry point."""
    logger.info("Starting LLM server...")

    # Load model at startup
    if not load_model():
        logger.error("Failed to load model, exiting")
        return

    # Start Flask server
    port = int(os.getenv("PORT", "8000"))
    logger.info(f"Starting server on port {port}")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )


if __name__ == "__main__":
    main()
