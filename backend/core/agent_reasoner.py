import os
import httpx
import json
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class AgentReasoner:
    def __init__(self):
        self.provider = os.environ.get("LLM_PROVIDER", "ollama")
        self.ollama_base_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
        self.ollama_model = os.environ.get("OLLAMA_MODEL", "llama3")
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY", "")

    def infer_tool(self, prompt: str, role: str) -> Dict[str, Any]:
        """
        Uses LLM to decide which tool to use and what arguments to pass.
        Returns: {"tool_name": str, "args": dict, "thought": str}
        """
        system_prompt = (
            "You are an AI Agent Orchestrator. Your goal is to select the BEST tool or provide a direct answer. "
            "Available tools:\n"
            "- web_search(query): General knowledge, up-to-date info.\n"
            "- calculator(expression): Math and calculations.\n"
            "- summarizer(text): Condensing long text.\n"
            "- customer_lookup(customer_id): Finding customer details.\n"
            "- issue_tracker(issue_id): Checking support ticket status.\n"
            "- db_read(table): Accessing internal database tables.\n\n"
            "If the user is just greeting you, asking about you, or asking a question that doesn't need data from a specific tool, select tool_name: 'none'.\n"
            "Respond ONLY in JSON: {\"tool_name\": \"...\", \"args\": {...}, \"thought\": \"your reasoning\"}"
        )

        if self.provider == "ollama":
            return self._reason_ollama(system_prompt, prompt)
        else:
            return self._reason_gemini(system_prompt, prompt)

    def _reason_ollama(self, system_prompt: str, prompt: str) -> Dict[str, Any]:
        url = f"{self.ollama_base_url}/api/chat"
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"User Request: {prompt}"}
            ],
            "stream": False,
            "format": "json"
        }
        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                content = data.get("message", {}).get("content", "")
                result = json.loads(content)
                return {
                    "tool_name": result.get("tool_name", "web_search"),
                    "args": result.get("args", {"query": prompt}),
                    "thought": result.get("thought", "Automated reasoning.")
                }
        except Exception as e:
            logger.error(f"Ollama Reasoner Error: {e}")
            return {"tool_name": "web_search", "args": {"query": prompt}, "thought": "Fallback due to error."}

    def _reason_gemini(self, system_prompt: str, prompt: str) -> Dict[str, Any]:
        # Fallback to simple keyword inference if Gemini reasoning fails or key is missing
        if not self.gemini_api_key:
             return {"tool_name": "web_search", "args": {"query": prompt}, "thought": "No Gemini key, keyword fallback."}
             
        # (Gemini implementation similar to evaluator omitted for brevity, or implemented if needed)
        # For now, let's just use the keyword inference as a safe fallback for Gemini in this "Offline-First" PR
        return self._keyword_fallback(prompt)

    def _keyword_fallback(self, prompt: str) -> Dict[str, Any]:
        lowered = prompt.lower()
        if "calculate" in lowered or "math" in lowered:
            return {"tool_name": "calculator", "args": {"expression": prompt}, "thought": "Keyword: math"}
        if "customer" in lowered and "lookup" in lowered:
            return {"tool_name": "customer_lookup", "args": {"customer_id": "C-123"}, "thought": "Keyword: customer"}
        return {"tool_name": "web_search", "args": {"query": prompt}, "thought": "Keyword: default"}

    def synthesize_response(self, prompt: str, tool_result: str, thought: str) -> str:
        """
        Takes the original prompt and tool results to generate a natural language answer.
        """
        system_instruction = (
            "You are AegisMind, a sophisticated and secure AI Agent. "
            "Your goal is to answer the user's question based ONLY on the provided tool result. "
            "Be professional, helpful, and concise. "
            "If the tool result is empty or irrelevant, politely inform the user."
        )
        
        user_context = (
            f"USER QUESTION: {prompt}\n"
            f"MY INTERNAL THOUGHT: {thought}\n"
            f"DATA RETRIEVED (TOOL RESULT): {tool_result}"
        )

        if self.provider == "ollama":
            return self._synthesize_ollama(system_instruction, user_context)
        else:
            return f"Answer based on data: {tool_result}"

    def _synthesize_ollama(self, system_instruction: str, context: str) -> str:
        url = f"{self.ollama_base_url}/api/chat"
        payload = {
            "model": self.ollama_model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": context}
            ],
            "stream": False
        }
        try:
            with httpx.Client(timeout=120.0) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()
                return data.get("message", {}).get("content", "I processed your request but couldn't generate a summary.")
        except Exception as e:
            logger.error(f"Ollama Synthesis Error: {e}")
            return "Local reasoning engine error. Please check Ollama connectivity."

agent_reasoner = AgentReasoner()
