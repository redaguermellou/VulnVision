import os
import logging
import time
import hashlib
from typing import Any, Dict, List, Optional
from django.core.cache import cache
import google.generativeai as genai
from google.api_core import exceptions

logger = logging.getLogger(__name__)

# Prompt Templates
VULNERABILITY_EXPLANATION_PROMPT = """
You are a senior security researcher. Explain the following vulnerability finding in detail:
Vulnerability Data: {vulnerability_data}

Focus on:
1. What the vulnerability is.
2. The technical root cause.
3. Potential impact on the system.
4. How an attacker might exploit it.

Format the output in clear Markdown with bold headers.
"""

REMEDIATION_PROMPT = """
You are a security engineer. Suggest remediation steps for the following vulnerability:
Vulnerability Name: {vulnerability_name}
Context: {context}

Provide:
1. Short term fix (mitigation).
2. Long term fix (patching/configuration).
3. Best practices to prevent this in the future.

Format the output in clear Markdown with actionable steps.
"""

SECURITY_AUDIT_PROMPT = """
Perform a high-level security audit based on the target information provided:
Target Info: {target_info}

Identify potential areas of concern and provide general security recommendations for this environment.
Focus on network exposure, service versions (if provided), and common misconfigurations.
"""

SECURITY_QUESTION_PROMPT = """
Context: {context}
Question: {question}

Answer the security-related question accurately based on the provided context. 
If the context doesn't contain the answer, use your general security knowledge but specify that it's general advice.
"""

class GemmaIntegration:
    """
    Service class for interacting with Google Gemma AI for security analysis.
    """
    def __init__(self):
        self.api_key = os.getenv('GEMINI_API_KEY')
        # Using Gemma 2 as Gemma 3 is not commercially available yet, 
        # but the logic allows switching to Gemma 3 when released.
        self.model_name = os.getenv('GEMMA_MODEL_NAME', 'gemma-2-27b-it') 
        
        if not self.api_key:
            logger.warning("GEMINI_API_KEY not found in environment variables. Gemma integration will fail.")
        
        try:
            genai.configure(api_key=self.api_key)
            self.model = genai.GenerativeModel(self.model_name)
        except Exception as e:
            logger.error(f"Failed to initialize Google Generative AI: {e}")
            self.model = None
        
        # Simple rate limiting settings
        self.last_request_time: float = 0.0
        self.min_interval = 2.0 # Minimum seconds between requests

    def _wait_for_rate_limit(self):
        """Ensures at least min_interval seconds between API calls"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            wait_time = self.min_interval - elapsed
            logger.info(f"Rate limiting: waiting {wait_time:.2f}s")
            time.sleep(wait_time)
        self.last_request_time = time.time()

    def _get_cache_key(self, prefix: str, data: str) -> str:
        """Generates a stable cache key"""
        return f"gemma_{prefix}_{hashlib.md5(data.encode()).hexdigest()}"

    def _generate_content(self, prompt: str, cache_prefix: Optional[str] = None) -> str:
        """
        Generic method to generate content with error handling, rate limiting, and optional caching.
        """
        if not self.api_key or not self.model:
            return "Error: AI Service not properly configured (Missing API Key)."

        cache_key = self._get_cache_key(cache_prefix, prompt) if cache_prefix else None
        
        if cache_key:
            cached = cache.get(cache_key)
            if cached:
                logger.info(f"Returning cached AI response for {cache_prefix}")
                return cached

        self._wait_for_rate_limit()
        
        try:
            # Add safety settings for security research (allowing discussion of vulnerabilities)
            safety_settings = [
                {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"},
            ]
            
            response = self.model.generate_content(prompt, safety_settings=safety_settings)
            
            if not response.text:
                return "Error: Empty response from AI."
                
            result = response.text
            
            if cache_key:
                cache.set(cache_key, result, timeout=3600 * 24) # Cache for 24 hours
            
            return result

        except exceptions.ResourceExhausted:
            logger.error("Gemma API rate limit exceeded.")
            return "Error: AI Service rate limit exceeded. Please try again in 1 minute."
        except exceptions.InvalidArgument as e:
            logger.error(f"Invalid argument to AI API: {e}")
            return "Error: Invalid input provided to AI."
        except exceptions.DeadlineExceeded:
            logger.error("Gemma API request timed out.")
            return "Error: AI analysis timed out."
        except Exception as e:
            logger.error(f"Unexpected error in Gemma integration: {e}")
            error_str = str(e)
            if "finish_reason" in error_str:
                 return "Error: Content filtered by safety filters. Try rephrasing."
            return f"Error: AI service encountered an error: {error_str[:100]}"

    def explain_vulnerability(self, vulnerability_data: Any) -> str:
        """Explains a vulnerability finding in detail."""
        data_str = str(vulnerability_data)
        prompt = VULNERABILITY_EXPLANATION_PROMPT.format(vulnerability_data=data_str)
        return self._generate_content(prompt, "explain")

    def suggest_remediation(self, vulnerability_name: str, context: Optional[str] = None) -> str:
        """Suggests remediation steps for a specific vulnerability."""
        ctx = context or "Generic network environment"
        prompt = REMEDIATION_PROMPT.format(vulnerability_name=vulnerability_name, context=ctx)
        return self._generate_content(prompt, "remedy")

    def generate_security_recommendations(self, target_info: Any) -> str:
        """Generates general security recommendations for a scanned target."""
        target_str = str(target_info)
        prompt = SECURITY_AUDIT_PROMPT.format(target_info=target_str)
        return self._generate_content(prompt, "audit")

    def answer_security_question(self, question: str, context: Optional[str] = None) -> str:
        """Answers a specific security question given some context."""
        ctx = context or "Cybersecurity general knowledge"
        prompt = SECURITY_QUESTION_PROMPT.format(question=question, context=ctx)
        return self._generate_content(prompt, "qa")
