"""
Enhanced Safety Filter for Open WebUI
Filters user inputs and model outputs for harmful content using a safety model, with optional policy augmentation via direct API calls.
"""

from typing import Optional, Callable, Awaitable, List, Dict, Any
import aiohttp
from pydantic import BaseModel, Field
import unicodedata
import datetime  # For datetime logging
from tempfile import SpooledTemporaryFile

# Local Open WebUI imports (guarded for environments outside runtime)
try:
    from open_webui.utils.chat import generate_chat_completion  # type: ignore
    from open_webui.models.knowledge import Knowledges  # type: ignore
    from open_webui.models.users import Users  # type: ignore
    from open_webui.routers.files import upload_file_handler  # type: ignore
    from open_webui.routers.retrieval import process_file, ProcessFileForm  # type: ignore
    from fastapi import UploadFile  # type: ignore
    from fastapi.concurrency import run_in_threadpool  # type: ignore
except ImportError:  # pragma: no cover - guarded optional runtime deps
    generate_chat_completion = None
    Knowledges = None
    Users = None
    upload_file_handler = None
    process_file = None
    ProcessFileForm = None
    UploadFile = None
    run_in_threadpool = None



class Filter:
    """
    Open WebUI Filter implementation for content safety.
    """
    def _print_safely(self, *parts: Any) -> None:
        safe_parts: List[Any] = []
        for p in parts:
            # Truncate long strings
            if isinstance(p, str):
                p = self._truncate(p)
            safe_parts.append(p)
        try:
            print(*safe_parts)
        except Exception:
            # Best-effort: avoid crashing due to logging
            pass

    class Valves(BaseModel):
        priority: int = -1
        enabled: bool = True
        safety_model_id: str = "prompt-safety-and-policy-violation-detector"  # Now expects the model ID directly

        block_on_unsafe: bool = True
        check_input: bool = True
        check_output: bool = True
        enable_full_debug: bool = Field(
            default=False,
            description="Enable heavy debugging logs, including payloads/results (masked & truncated).",
        )
        enable_step_debug: bool = Field(
            default=False,
            description="Enable step-by-step progress logs (concise, truncated).",
        )
        violation_kb: str = Field(
            default="Safety Violations",
            description="Knowledge base name for logging violations.",
        )
        harm_categories: List[str] = [
            "Dangerous Content",
            "Hate Speech",
            "Harassment",
            "Sexually Explicit",
        ]
            # Unused valves removed: api_url, api_key, user_agent, compliance_kb, infringement_kb, max_results, reranker_results, relevance_threshold, enable_hybrid_search

    def __init__(self):
        self.valves = self.Valves()

    # Debugging helpers
    def _is_step_debug(self) -> bool:
        return bool(getattr(self.valves, "enable_step_debug", False) or getattr(self.valves, "enable_full_debug", False))

    def _is_full_debug(self) -> bool:
        return bool(getattr(self.valves, "enable_full_debug", False))

    def _truncate(self, text: Any, n: int = 200) -> Any:
        try:
            s = str(text)
        except Exception:
            return text
        if len(s) <= n:
            return s
        return s[: n - 1] + "…"

    def _dbg_step(self, *parts: Any) -> None:
        if self._is_step_debug():
            self._print_safely(*parts)

    def _dbg_full(self, *parts: Any) -> None:
        if self._is_full_debug():
            self._print_safely(*parts)

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        """
        Filter incoming user messages for harmful content.
        """
        self._dbg_full("Inlet called with body:", body)  # heavy: full body
        if not self.valves.enabled or not self.valves.check_input:
            self._dbg_step("Inlet skipped: Disabled or no check_input")  # Log skip
            return body

        messages = body.get("messages", [])
        if not messages:
            self._dbg_step("Inlet skipped: No messages")  # Log skip
            return body

        # Check the last user message
        last_message = messages[-1]
        if last_message.get("role") == "user":
            user_content = last_message.get("content", "")
            self._dbg_step("Checking user content:", self._truncate(user_content, 100))

            if __event_emitter__:
                self._dbg_step("Emitting status: Checking content safety...")  # Log emit
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Checking content safety...",
                            "done": False,
                        },
                    }
                )

            is_safe, reason = await self.check_safety(user_content, __user__, __request__)
            self._dbg_step(f"Safety check result: is_safe={is_safe} reason={reason}")

            if __event_emitter__:
                self._dbg_step("Emitting status: Safety check complete")  # Log emit
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"Safety check complete: {'✓ Safe' if is_safe else f'⚠ {reason} detected'}",
                            "done": True,
                        },
                    }
                )

            if not is_safe and self.valves.block_on_unsafe:
                model_name = body.get("model", "unknown")
                await self.log_violation(__user__, user_content, reason, __request__, model_name=model_name)
                self._dbg_step(f"Blocking input content: {reason}")
                self._dbg_full("Blocking input content payload:", user_content)
                if __event_emitter__:
                    self._dbg_step("Emitting status: Content blocked by safety filter")  # Log emit
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {
                                "description": "Content blocked by safety filter",
                                "done": True,
                            },
                        }
                    )
                raise ValueError(f"Content blocked by safety filter: {reason}")

        return body

    async def outlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        """
        Filter outgoing model responses for harmful content.
        """
        self._dbg_full("Outlet called with body:", body)  # heavy: full body
        if not self.valves.enabled or not self.valves.check_output:
            self._dbg_step("Outlet skipped: Disabled or no check_output")  # Log skip
            return body

        messages = body.get("messages", [])
        if not messages:
            self._dbg_step("Outlet skipped: No messages")  # Log skip
            return body

        # Check the last assistant message
        last_message = messages[-1]
        if last_message.get("role") == "assistant":
            assistant_content = last_message.get("content", "")
            self._dbg_step("Checking assistant content:", self._truncate(assistant_content, 100))

            if __event_emitter__:
                self._dbg_step("Emitting status: Checking response safety...")  # Log emit
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Checking response safety...",
                            "done": False,
                        },
                    }
                )

            is_safe, reason = await self.check_safety(assistant_content, __user__, __request__)
            self._dbg_step(f"Safety check result: is_safe={is_safe} reason={reason}")

            if __event_emitter__:
                self._dbg_step("Emitting status: Safety check complete")  # Log emit
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": f"Safety check complete: {'✓ Safe' if is_safe else f'⚠ {reason} detected'}",
                            "done": True,
                        },
                    }
                )

            if not is_safe and self.valves.block_on_unsafe:
                model_name = body.get("model", "unknown")
                await self.log_violation(__user__, assistant_content, reason, __request__, model_name=model_name)
                self._dbg_step(f"Blocking output content: {reason}")
                self._dbg_full("Blocking output content payload:", assistant_content)
                if __event_emitter__:
                    self._dbg_step("Emitting status: Response blocked by safety filter")  # Log emit
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {
                                "description": "Response blocked by safety filter",
                                "done": True,
                            },
                        }
                    )

                # Replace unsafe content with safe message
                last_message["content"] = (
                    "I apologize, but I cannot provide that response as it "
                    f"contains potentially harmful content ({reason}). "
                    "Please rephrase your request."
                )

        return body


    async def log_violation(
        self, user: Optional[dict], content: str, reason: str, request: Optional[Any] = None, model_name: Optional[str] = None
    ) -> None:
        """
        Log violation to the configured Knowledge Base.
        """
        self._dbg_step("log_violation called")
        
        # 1. Basic local logging (always do this)
        try:
            timestamp = datetime.datetime.now().isoformat()
            record = {
                "user_id": user.get("id", "unknown") if user else "unknown",
                "datetime": timestamp,
                "model": model_name or "unknown",
                "reason": reason,
                "content": self._truncate(content, 400),
            }
            self._dbg_full("Violation Record:", record)
        except Exception as e:
            self._dbg_step(f"log_violation local logging error: {e}")

        # 2. Remote KB logging
        if not self.valves.violation_kb or self.valves.violation_kb.lower() == "none":
            self._dbg_step("Violation KB logging disabled (violation_kb not set)")
            return

        if not all([upload_file_handler, process_file, Knowledges, Users, run_in_threadpool]):
            self._dbg_step("Required OpenWebUI modules not available for KB logging")
            return

        if not request or not user:
            self._dbg_step("Missing request or user context for KB logging")
            return

        try:
            # Resolve User object
            user_obj = await run_in_threadpool(Users.get_user_by_id, str(user["id"]))
            if not user_obj:
                self._dbg_step("Could not resolve User object")
                return

            # Find KB
            kb_name = self.valves.violation_kb.strip()
            kb_id = None
            
            # Try to find by ID or Name
            kbs = await run_in_threadpool(Knowledges.get_knowledge_bases_by_user_id, user_obj.id, "write")
            if kbs:
                for kb in kbs:
                    if kb.id == kb_name or kb.name == kb_name:
                        kb_id = kb.id
                        break
            
            if not kb_id:
                self._dbg_step(f"Violation KB '{kb_name}' not found for user")
                return

            # Prepare content
            full_log_content = (
                f"--- Safety Violation Report ---\n"
                f"Timestamp: {timestamp}\n"
                f"User ID: {user.get('id', 'unknown')}\n"
                f"User Name: {user.get('name', 'unknown')}\n"
                f"User Email: {user.get('email', 'unknown')}\n"
                f"Model: {model_name or 'unknown'}\n"
                f"Reason: {reason}\n"
                f"--- Content ---\n"
                f"{content}\n"
                f"-------------------------------\n"
            )

            filename = f"safety_violation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            # Upload File
            upload = UploadFile(
                filename=filename,
                file=SpooledTemporaryFile(max_size=1024 * 1024),
                headers={"content-type": "text/plain"},
            )
            upload.file.write(full_log_content.encode("utf-8"))
            upload.file.seek(0)

            try:
                file_data = await run_in_threadpool(
                    upload_file_handler,
                    request,
                    upload,
                    {"source": "safety_filter", "type": "violation_report"}, # metadata
                    False, # process
                    False, # process_in_background
                    user_obj,
                    None,
                )
            finally:
                await upload.close()

            # Handle Pydantic vs Dict
            file_id = getattr(file_data, "id", None)
            if file_id is None and isinstance(file_data, dict):
                file_id = file_data.get("id")
            
            if not file_id:
                self._dbg_step("Failed to upload violation report file")
                return

            # Attach to KB
            try:
                await run_in_threadpool(
                    Knowledges.add_file_to_knowledge_by_id,
                    kb_id,
                    file_id,
                    user_obj.id,
                )
            except AttributeError:
                 # Fallback for older versions
                knowledge = Knowledges.get_knowledge_by_id(id=kb_id)
                if knowledge:
                    data = getattr(knowledge, "data", None) or {}
                    file_ids = data.get("file_ids", [])
                    if file_id not in file_ids:
                        file_ids.append(file_id)
                        data["file_ids"] = file_ids
                        Knowledges.update_knowledge_data_by_id(id=kb_id, data=data)

            # Process File
            await run_in_threadpool(
                process_file,
                request,
                ProcessFileForm(file_id=file_id, collection_name=kb_id, content=full_log_content),
                user_obj,
            )
            
            self._dbg_step(f"Violation logged to KB '{kb_name}' (File ID: {file_id})")

        except Exception as e:
            self._dbg_step(f"Error logging violation to KB: {e}")


    # log_violation removed: KB logging is no longer supported.


    # _get_knowledge_bases removed: KB logic is no longer supported.


    # _find_knowledge_base_id removed: KB logic is no longer supported.


    # _perform_search removed: KB logic is no longer supported.


    # _format_results removed: KB logic is no longer supported.


    async def check_safety(
        self, content: str, user: Optional[dict] = None, __request__: Optional[Any] = None
    ) -> tuple[bool, str]:
        """
        Check content safety using a safety model via Open WebUI internal library.
        Supports multiple safety model formats (ShieldGemma, Llama Guard, etc.)

        Returns:
            tuple: (is_safe: bool, reason: str)
        """
        try:
            self._dbg_step(f"Starting safety check for content: '{self._truncate(content, 100)}...'")  # start
            # Sanitize: Remove all Unicode controls, preserve multilingual chars
            sanitized_content = "".join(
                c for c in content if not unicodedata.category(c).startswith("C")
            )
            self._dbg_step("Sanitized content:", self._truncate(sanitized_content, 100))  # Log sanitized


            # Build prompt (content only, no policy augmentation)
            prompt = self.build_safety_prompt(sanitized_content)
            self._dbg_full("Safety prompt:", self._truncate(prompt, 200))  # heavy

            # Use Open WebUI's internal API to call the safety model (model ID is now provided directly)
            try:
                from open_webui.utils.chat import generate_chat_completion
            except ImportError as e:
                self._dbg_step(f"ImportError: {e} - fail-blocking")
                # Fail-closed: block if internal library cannot be imported
                return False, "Safety model unavailable"

            payload = {
                "model": self.valves.safety_model_id,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
            self._dbg_full("Safety payload:", payload)  # heavy

            # Use internal generate_chat_completion with __request__ and user
            response = await generate_chat_completion(
                request=__request__,
                form_data=payload,
                user=user,
                bypass_filter=True,
            )

            self._dbg_step(f"Safety model response received")

            # Handle response
            if isinstance(response, dict):
                choices = response.get("choices", [])
                if not choices or not isinstance(choices, list) or not choices:
                    self._dbg_step("No 'choices' array in model response")
                    return True, ""
                message = choices[0].get("message", {})
                response_text = message.get("content", "")
            else:
                self._dbg_step(f"Unexpected response type: {type(response)}")
                return True, ""

            self._dbg_step(f"Safety model response: {self._truncate(response_text, 200)}")
            return self._parse_safety_response(response_text)

        except Exception as e:
            self._dbg_step(f"Safety check exception: {e}")  # Log exception details
            # Fail-open: avoid blocking due to unexpected exceptions
            return True, ""

    def _parse_safety_response(self, response_text: str) -> tuple[bool, str]:
        """
        Parse safety model response supporting multiple formats:
        - ShieldGemma: "Yes"/"No" or "Safe"/"Unsafe: [category]"
        - Llama Guard: "safe" or "unsafe [category]" (supports multiple categories)
        - Generic: Any response with unsafe/harmful indicators
        
        Supports multiple categories for granular logging.
        """
        self._dbg_step("Parsing safety response:", self._truncate(response_text, 200))  # Log entry
        if not response_text:
            self._dbg_step("Empty safety response - defaulting to safe")  # Log empty response
            return True, ""

        response_lower = response_text.lower().strip()

        # Explicit "safe" response (no "unsafe" modifier)
        if response_lower == "safe" or (
            response_lower.startswith("safe") and "unsafe" not in response_lower
        ):
            self._dbg_step("Safe response")  # Log safe
            return True, ""

        # Llama Guard format: "unsafe" with category (S1-S11)
        if response_lower.startswith("unsafe"):
            # Extract all categories if present
            import re
            category_matches = re.findall(r's(\d+)', response_lower)
            if category_matches:
                category_map = {
                    "1": "Violent Crimes",
                    "2": "Non-Violent Crimes",
                    "3": "Sex Crimes",
                    "4": "Child Exploitation",
                    "5": "Specialized Advice",
                    "6": "Privacy Violation",
                    "7": "Intellectual Property / Policy Violation",
                    "8": "Indiscriminate Weapons",
                    "9": "Hate Speech",
                    "10": "Self-Harm",
                    "11": "Sexual Content"
                }
                # Build reason string with all detected categories
                reasons = []
                for cat_num in category_matches:
                    cat_name = category_map.get(cat_num, f"S{cat_num}")
                    reasons.append(f"{cat_name} (S{cat_num})")
                
                reason = ", ".join(reasons)
                self._dbg_step(f"Unsafe content detected: {reason}")
                return False, reason
            
            # Generic unsafe without category - treat as harmful content
            self._dbg_step("Unsafe content detected (generic)")
            return False, "Harmful Content"

        # ShieldGemma/Generic: Check for unsafe indicators
        unsafe_indicators = [
            "unsafe",
            "yes",
            "harmful",
            "violation",
            "inappropriate",
            "no",
        ]
        if any(indicator in response_lower for indicator in unsafe_indicators):
            # Try to extract category from response
            for category in self.valves.harm_categories:
                if category.lower() in response_lower:
                    self._dbg_step(f"Unsafe detected: {category}")  # Log
                    return False, category

            # Check for common category keywords
            category_map = {
                "violence": "Dangerous Content",
                "hate": "Hate Speech",
                "harass": "Harassment",
                "sexual": "Sexually Explicit",
                "explicit": "Sexually Explicit",
            }
            for keyword, category in category_map.items():
                if keyword in response_lower:
                    self._dbg_step(f"Unsafe detected: {category}")  # Log
                    return False, category

            self._dbg_step("Unsafe detected: Harmful Content")  # Log generic unsafe
            return False, "Harmful Content"

        # Default to safe if no unsafe indicators found
        self._dbg_step("Defaulting to safe: No indicators found")  # Log default
        return True, ""

    # Model lookup and resolution removed: safety_model_id must be set directly to the model ID.
    
    # Prompt injection detection removed for separation of concerns.

    def build_safety_prompt(self, content: str, policy_snippets: str = "") -> str:
        """
        Build prompt with content and policies only.
        NO HARD-CODED INSTRUCTIONS - model's system prompt defines classification logic.
        """
        self._dbg_step("Building safety prompt")  # Log entry
        
        if policy_snippets:
            prompt = f"{content}\n\nCompany Policies:\n{policy_snippets}"
        else:
            prompt = content
        
        return prompt
