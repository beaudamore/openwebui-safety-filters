"""
Safety Filter for Open WebUI
Filters user inputs and model outputs for harmful content using a safety model.
"""

from typing import Optional, Callable, Awaitable, List
import aiohttp
from pydantic import BaseModel


class Filter:
    """
    Open WebUI Filter implementation for content safety.
    """
    
    class Valves(BaseModel):
        priority: int = 0
        enabled: bool = True
        api_url: str = "http://host.docker.internal:8080"
        api_key: str = ""
        user_agent: str = "Safety-Filter/1.0"
        safety_model: str = "shieldgemma:2b"
        block_on_unsafe: bool = True
        check_input: bool = True
        check_output: bool = True
        harm_categories: List[str] = [
            "Dangerous Content",
            "Hate Speech",
            "Harassment",
            "Sexually Explicit"
        ]
    
    def __init__(self):
        self.valves = self.Valves()
    
    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
    ) -> dict:
        """
        Filter incoming user messages for harmful content.
        """
        if not self.valves.enabled or not self.valves.check_input:
            return body
            
        messages = body.get("messages", [])
        if not messages:
            return body
            
        # Check the last user message
        last_message = messages[-1]
        if last_message.get("role") == "user":
            user_content = last_message.get("content", "")
            
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Checking content safety...",
                            "done": False
                        }
                    }
                )
            
            is_safe, reason = await self.check_safety(user_content, __user__)
            
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"Safety check complete: {'✓ Safe' if is_safe else f'⚠ {reason} detected'}",
                            "done": True
                        }
                    }
                )
            
            if not is_safe and self.valves.block_on_unsafe:
                if __event_emitter__:
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {
                                "description": "Content blocked by safety filter",
                                "done": True
                            }
                        }
                    )
                raise ValueError(
                    f"Content blocked by safety filter: {reason}"
                )
        
        return body
    
    async def outlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
    ) -> dict:
        """
        Filter outgoing model responses for harmful content.
        """
        if not self.valves.enabled or not self.valves.check_output:
            return body
            
        messages = body.get("messages", [])
        if not messages:
            return body
            
        # Check the last assistant message
        last_message = messages[-1]
        if last_message.get("role") == "assistant":
            assistant_content = last_message.get("content", "")
            
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Checking response safety...",
                            "done": False
                        }
                    }
                )
            
            is_safe, reason = await self.check_safety(assistant_content, __user__)
            
            if __event_emitter__:
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"Safety check complete: {'✓ Safe' if is_safe else f'⚠ {reason} detected'}",
                            "done": True
                        }
                    }
                )
            
            if not is_safe and self.valves.block_on_unsafe:
                if __event_emitter__:
                    await __event_emitter__(
                        {
                            "type": "status", 
                            "data": {
                                "description": "Response blocked by safety filter",
                                "done": True
                            }
                        }
                    )
                
                # Replace unsafe content with safe message
                last_message["content"] = (
                    "I apologize, but I cannot provide that response as it "
                    f"contains potentially harmful content ({reason}). "
                    "Please rephrase your request."
                )
        
        return body
    
    async def check_safety(self, content: str, user: Optional[dict] = None) -> tuple[bool, str]:
        """
        Check content safety using a safety model via Open WebUI API.
        Supports multiple safety model formats (ShieldGemma, Llama Guard, etc.)
        
        Returns:
            tuple: (is_safe: bool, reason: str)
        """
        try:
            prompt = self.build_safety_prompt(content)
            
            # Use Open WebUI's internal API to call the safety model
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.valves.safety_model,
                    "messages": [
                        {
                            "role": "user",
                            "content": prompt
                        }
                    ],
                    "stream": False
                }
                
                headers = {}
                if self.valves.api_key:
                    headers["Authorization"] = f"Bearer {self.valves.api_key}"
                if self.valves.user_agent:
                    headers["User-Agent"] = self.valves.user_agent
                
                # Call Open WebUI's chat completion endpoint
                async with session.post(
                    f"{self.valves.api_url}/api/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        print(f"Safety model error: {response.status}")
                        return True, ""  # Fail open
                    
                    result = await response.json()
                    response_text = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                    
                    # Log the raw response for debugging
                    print(f"Safety model response: {response_text}")
                    
                    return self._parse_safety_response(response_text)
            
        except Exception as e:
            print(f"Safety check error: {e}")
            return True, ""  # Fail open on errors
    
    def _parse_safety_response(self, response_text: str) -> tuple[bool, str]:
        """
        Parse safety model response supporting multiple formats:
        - ShieldGemma: "Yes"/"No" or "Safe"/"Unsafe: [category]"
        - Llama Guard: "safe" or "unsafe\n[category]"
        - Generic: Any response with unsafe/harmful indicators
        """
        if not response_text:
            return True, ""
        
        response_lower = response_text.lower().strip()
        
        # Llama Guard format: starts with "unsafe" on its own line
        if response_lower.startswith("unsafe"):
            lines = response_text.strip().split('\n')
            if len(lines) > 1:
                # Extract category from second line
                category = lines[1].strip()
                # Try to match against known categories
                for harm_cat in self.valves.harm_categories:
                    if harm_cat.lower() in category.lower():
                        return False, harm_cat
                return False, category.title() if category else "Harmful Content"
            return False, "Harmful Content"
        
        # Explicit "safe" response (no "unsafe" modifier)
        if response_lower == "safe" or (response_lower.startswith("safe") and "unsafe" not in response_lower):
            return True, ""
        
        # ShieldGemma/Generic: Check for unsafe indicators
        unsafe_indicators = ["unsafe", "yes", "harmful", "violation", "inappropriate"]
        if any(indicator in response_lower for indicator in unsafe_indicators):
            # Try to extract category from response
            for category in self.valves.harm_categories:
                if category.lower() in response_lower:
                    return False, category
            
            # Check for common category keywords
            category_map = {
                "violence": "Dangerous Content",
                "hate": "Hate Speech",
                "harass": "Harassment",
                "sexual": "Sexually Explicit",
                "explicit": "Sexually Explicit"
            }
            for keyword, category in category_map.items():
                if keyword in response_lower:
                    return False, category
            
            return False, "Harmful Content"
        
        # Default to safe if no unsafe indicators found
        return True, ""
    
    def build_safety_prompt(self, content: str) -> str:
        """
        Build a universal prompt that works across multiple safety models.
        Optimized for ShieldGemma, Llama Guard, and similar classifiers.
        """
        return f"""Classify if the following content is safe or unsafe.

Content: {content}

Respond with either:
- "safe" if the content is acceptable
- "unsafe" followed by the harm category (violence, hate speech, harassment, sexual content, dangerous content) if harmful

Response:"""
