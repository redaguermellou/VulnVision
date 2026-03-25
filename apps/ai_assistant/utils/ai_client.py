import json
import logging
import requests
from django.conf import settings

logger = logging.getLogger(__name__)

class AIClient:
    def __init__(self):
        self.api_key = getattr(settings, 'GEMINI_API_KEY', None)
        self.model_name = getattr(settings, 'GEMMA_MODEL_NAME', 'gemini-1.5-flash')

    def get_response(self, messages, context_text=""):
        if not self.api_key:
            return "AI configuration missing. Please check API key. Make sure GEMINI_API_KEY is set in your .env file."

        contents = []
        for msg in messages[:-1]:
            role = "user" if msg['role'] == 'user' else "model"
            if contents and contents[-1]['role'] == role:
                contents[-1]['parts'][0]['text'] += f"\n\n{msg['content']}"
            else:
                contents.append({"role": role, "parts": [{"text": msg['content']}]})
            
        system_instruction = f"""
        You are VulnVision AI, a specialized security assistant.
        Your goal is to help users analyze security scans and vulnerabilities.
        
        Context for this session:
        {context_text}
        
        Rules:
        1. Be professional and technical.
        2. Provide actionable remediation steps.
        3. Reference specific CVEs or CWEs if mentioned in context.
        4. If asked to perform illegal actions, refuse politely and explain the ethical boundaries.
        5. Format your output in Markdown.
        """
        
        current_prompt = f"{system_instruction}\n\nUser Question: {messages[-1]['content']}"
        if contents and contents[-1]['role'] == 'user':
            contents[-1]['parts'][0]['text'] += f"\n\n{current_prompt}"
        else:
            contents.append({"role": "user", "parts": [{"text": current_prompt}]})
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        
        try:
            response = requests.post(url, json={"contents": contents}, headers={'Content-Type': 'application/json'}, timeout=30)
            if response.status_code == 200:
                data = response.json()
                try:
                    return data['candidates'][0]['content']['parts'][0]['text']
                except (KeyError, IndexError):
                    return "Error: Could not parse completion data from API."
            else:
                return f"API Error ({response.status_code}): Please verify your API Key is correct."
        except requests.exceptions.Timeout:
            return "The AI Intelligence engine is currently taking too long to respond (Timeout). Please try again or check your network."
        except Exception as e:
            logger.error(f"Error getting AI response: {str(e)}")
            return f"Error communicating with AI endpoint via REST API. Details: {str(e)}"

    def generate_suggested_questions(self, context_text):
        if not self.api_key:
            return ["Does this vulnerability have a public exploit?", "What is the recommended fix?", "How can I verify this is patched?"]
            
        prompt = f"Based on the following security context, suggest 3 highly relevant and technical follow-up questions a security researcher might ask. Return only a JSON list of strings.\nContext:\n{context_text}"
        
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model_name}:generateContent?key={self.api_key}"
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            response = requests.post(url, json=payload, headers={'Content-Type': 'application/json'}, timeout=30)
            if response.status_code == 200:
                text = response.json()['candidates'][0]['content']['parts'][0]['text'].strip()
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0].strip()
                elif "```" in text:
                    text = text.split("```")[1].strip()
                return json.loads(text)
        except Exception as e:
            logger.error(f"Error generating suggestions: {str(e)}")
            
        return [
            "How can I remediate the critical vulnerabilities?",
            "What are the potential impacts of these findings?",
            "How do I verify if these are false positives?"
        ]

def format_context(target=None, scan=None, vulnerabilities=None):
    context = []
    if target:
        context.append(f"Target: {target.name} ({target.ip_address or target.domain})")
        if target.description:
            context.append(f"Description: {target.description}")
            
    if scan:
        context.append(f"Scan Type: {scan.get_scan_type_display()}")
        context.append(f"Status: {scan.get_status_display()}")
        
    if vulnerabilities:
        context.append("\nVulnerabilities found:")
        for v in vulnerabilities[:10]: # Limit to top 10 for context window
            context.append(f"- [{v.severity.upper()}] {v.title}")
            context.append(f"  Description: {v.description[:200]}...")
            if v.cve_id: context.append(f"  CVE: {v.cve_id}")
            if v.component: context.append(f"  Component: {v.component}")
            
    return "\n".join(context)
