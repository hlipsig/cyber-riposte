"""
AI-powered incident narrative generation using Hugging Face models.

Generates human-readable security incident narratives that Tom will see
in the dossier, demonstrating AI-enhanced threat intelligence.
"""

import logging
import hashlib
import os
from typing import Dict, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class IncidentNarrator:
    """Generates human-readable narratives for security incidents using AI."""

    def __init__(self, model_name: str = None):
        """
        Initialize the AI narrator.

        Args:
            model_name: Hugging Face model to use (default: distilgpt2)
                Options:
                - "distilgpt2" (82MB, fast, recommended)
                - "gpt2" (548MB, better quality)
                - "facebook/opt-125m" (250MB, optimized)
        """
        self.model_name = model_name or os.getenv("AI_MODEL", "distilgpt2")
        self.enabled = os.getenv("AI_ENABLED", "true").lower() == "true"
        self.generator = None
        self.cache = {}  # Cache narratives by signature

        if self.enabled:
            self._initialize_model()
        else:
            logger.info("AI narrator disabled (AI_ENABLED=false)")

    def _initialize_model(self):
        """Load the model (lazy loading)."""
        try:
            logger.info(f"Loading Hugging Face model: {self.model_name}")

            from transformers import pipeline

            # Use text-generation pipeline
            self.generator = pipeline(
                "text-generation",
                model=self.model_name,
                device=-1,  # CPU (use 0 for GPU if available)
                max_new_tokens=150,
                do_sample=True,
                temperature=0.7,
                top_p=0.9,
                truncation=True,
            )

            logger.info(f"✅ AI model loaded: {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to load AI model: {e}")
            logger.warning("Falling back to template-based narratives")
            self.generator = None
            self.enabled = False

    def generate_incident_narrative(
        self,
        incident_data: Dict[str, Any],
        style: str = "technical"
    ) -> str:
        """
        Generate a narrative description of a security incident.

        Args:
            incident_data: Dictionary with incident details:
                - attacker_ip: IP address
                - detection_signature: What was detected
                - detection_confidence: Confidence score (0-1)
                - incident_id: Incident ID (optional)
            style: "technical", "executive", or "detailed"

        Returns:
            AI-generated narrative string
        """
        if not self.enabled or not self.generator:
            return self._fallback_narrative(incident_data)

        # Check cache
        cache_key = self._get_cache_key(incident_data, style)
        if cache_key in self.cache:
            logger.info("📦 Using cached AI narrative")
            return self.cache[cache_key]

        try:
            # Build the prompt
            prompt = self._build_prompt(incident_data, style)

            # Generate narrative
            logger.info(f"🤖 Generating AI narrative (style: {style})...")
            result = self.generator(
                prompt,
                max_new_tokens=150,
                num_return_sequences=1,
                pad_token_id=self.generator.tokenizer.eos_token_id,
                return_full_text=True,
            )

            # Extract generated text (remove prompt)
            full_text = result[0]['generated_text']
            narrative = full_text[len(prompt):].strip()

            # Clean up the output
            narrative = self._clean_narrative(narrative)

            # Add signature if narrative is too short
            if len(narrative) < 50:
                narrative = self._fallback_narrative(incident_data)

            # Cache it
            self.cache[cache_key] = narrative

            logger.info(f"✅ Generated AI narrative ({len(narrative)} chars)")
            return narrative

        except Exception as e:
            logger.error(f"AI narrative generation failed: {e}")
            return self._fallback_narrative(incident_data)

    def _build_prompt(self, incident_data: Dict[str, Any], style: str) -> str:
        """Build a prompt for the model based on incident data."""

        ip = incident_data.get('attacker_ip', 'unknown')
        signature = incident_data.get('detection_signature', 'unknown activity')
        confidence = incident_data.get('detection_confidence', 0.0)

        # Shorten signature for better prompts
        sig_lower = signature.lower()
        if 'nmap' in sig_lower:
            activity = "reconnaissance using Nmap scanning tools"
        elif 'nikto' in sig_lower:
            activity = "web vulnerability scanning"
        elif 'gobuster' in sig_lower or 'dirbuster' in sig_lower:
            activity = "directory brute-force enumeration"
        elif 'sqlmap' in sig_lower:
            activity = "SQL injection testing"
        elif 'high request rate' in sig_lower:
            activity = "high-volume request flooding"
        else:
            activity = "suspicious reconnaissance activity"

        if style == "technical":
            prompt = (
                f"Security incident report: An attacker from IP {ip} was detected "
                f"conducting {activity} against our infrastructure. "
                f"Detection confidence: {confidence*100:.0f}%. Technical analysis: "
            )
        elif style == "executive":
            prompt = (
                f"Executive briefing: Our security systems detected {activity} "
                f"originating from {ip}. The threat was identified with "
                f"{confidence*100:.0f}% confidence. Summary: "
            )
        else:  # detailed
            prompt = (
                f"Detailed threat intelligence report: "
                f"Source IP {ip} initiated {activity}. "
                f"Our detection systems flagged this behavior with {confidence*100:.0f}% confidence. "
                f"Analysis: The adversary "
            )

        return prompt

    def _clean_narrative(self, text: str) -> str:
        """Clean up AI-generated text."""
        # Remove extra whitespace
        text = ' '.join(text.split())

        # Stop at first double newline (paragraph break)
        if '\n\n' in text:
            text = text.split('\n\n')[0]

        # Ensure we have complete sentences
        sentences = []
        for sent in text.split('. '):
            sent = sent.strip()
            if sent and len(sent) > 10:  # Skip very short fragments
                if not sent.endswith('.'):
                    sent += '.'
                sentences.append(sent)

        # Take first 2-3 sentences
        if len(sentences) > 3:
            text = ' '.join(sentences[:3])
        else:
            text = ' '.join(sentences)

        # Final cleanup
        text = text.strip()

        # Make sure it ends properly
        if text and not text[-1] in '.!?':
            # Find last sentence boundary
            for delimiter in ['. ', '! ', '? ']:
                if delimiter in text:
                    text = text.rsplit(delimiter, 1)[0] + delimiter.strip()
                    break

        return text

    def _fallback_narrative(self, incident_data: Dict[str, Any]) -> str:
        """Fallback to template-based narrative if AI fails."""
        ip = incident_data.get('attacker_ip', 'unknown')
        signature = incident_data.get('detection_signature', 'unknown activity')
        confidence = incident_data.get('detection_confidence', 0.0)

        # Determine threat level
        if confidence >= 0.95:
            threat_level = "high-confidence"
            assessment = "indicating a deliberate reconnaissance effort"
        elif confidence >= 0.80:
            threat_level = "probable"
            assessment = "suggesting automated scanning activity"
        else:
            threat_level = "potential"
            assessment = "warranting further investigation"

        return (
            f"A {threat_level} security incident was detected from IP address {ip}. "
            f"The activity matched the signature: {signature}. "
            f"Our detection systems identified this threat with {confidence*100:.0f}% confidence, "
            f"{assessment}. This incident has been logged and is under automated monitoring."
        )

    def _get_cache_key(self, incident_data: Dict[str, Any], style: str) -> str:
        """Generate cache key for incident."""
        sig = incident_data.get('detection_signature', '')
        conf = incident_data.get('detection_confidence', 0.0)
        key_str = f"{sig}_{conf:.2f}_{style}"
        return hashlib.md5(key_str.encode()).hexdigest()


# Singleton instance
_narrator: Optional[IncidentNarrator] = None

def get_narrator() -> IncidentNarrator:
    """Get or create the singleton narrator instance."""
    global _narrator
    if _narrator is None:
        _narrator = IncidentNarrator()
    return _narrator


def generate_narrative(incident_data: Dict[str, Any], style: str = "technical") -> str:
    """
    Convenience function to generate a narrative.

    Args:
        incident_data: Incident details
        style: Narrative style

    Returns:
        AI-generated narrative
    """
    narrator = get_narrator()
    return narrator.generate_incident_narrative(incident_data, style)
