"""
Enhanced Safety Filter for Open WebUI
Filters user inputs and model outputs for harmful content using a safety model, with optional policy augmentation via direct API calls.
"""

from typing import Optional, Callable, Awaitable, List, Dict, Any
import aiohttp
from pydantic import BaseModel, Field
import unicodedata
import datetime  # For datetime logging


class Filter:
    """
    Open WebUI Filter implementation for content safety.
    """

    class Valves(BaseModel):
        priority: int = 0
        enabled: bool = True
        api_url: str = "http://host.docker.internal:3000"
        api_key: str = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjIyYjBkZTNkLTYxOTEtNDIwNC04MDkwLWJjNTg2MWQ4MWNlMCJ9.4yXjiINWv9jDz6SgpuBWp0zJgS5ySz3IayRUMms-Ixw"
        )
        user_agent: str = "Safety-Filter/1.0"
        safety_model: str = "Safety Filter"
        injection_detection_model: str = Field(
            default="Prompt Injection Detector",
            description="Model name for semantic prompt injection detection. The model's system prompt defines detection logic. Should return 'SAFE' or 'INJECTION' classification.",
        )
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
        harm_categories: List[str] = [
            "Dangerous Content",
            "Hate Speech",
            "Harassment",
            "Sexually Explicit",
        ]
        compliance_kb: str = Field(
            default="co-policies",
            description="Comma-separated knowledge base name(s) for compliance policies (e.g., 'hr-policies,ethics-guidelines'). Used to augment safety checks. Set to 'none' or empty for basic mode.",
        )
        infringement_kb: str = Field(
            default="policy-infringements",
            description="Knowledge base for logging infringements. Create this KB in UI if not exists.",
        )
        max_results: int = Field(
            default=3,
            description="Maximum number of results to retrieve per KB search (for policy augmentation).",
        )
        reranker_results: int = Field(
            default=0,
            description="Number of results to retain after reranking (0 disables reranking).",
        )
        relevance_threshold: float = Field(
            default=0.0,
            description="Minimum relevance score threshold for results (0.0-1.0).",
        )
        enable_hybrid_search: bool = Field(
            default=False, description="Enable hybrid search for KB queries."
        )

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
                self._dbg_step("Emitting status: Checking for prompt injection...")
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Checking for prompt injection...",
                            "done": False,
                        },
                    }
                )

            # PHASE 1: Semantic prompt injection detection (NO hard-coded patterns)
            is_injection_safe, injection_reason = await self._detect_prompt_injection_semantic(user_content)
            self._dbg_step(f"Injection check result: is_safe={is_injection_safe} reason={injection_reason}")

            if not is_injection_safe and self.valves.block_on_unsafe:
                await self.log_violation(__user__, user_content, f"Prompt Injection: {injection_reason}")
                self._dbg_step(f"Blocking input content: Prompt Injection detected - {injection_reason}")
                if __event_emitter__:
                    self._dbg_step("Emitting status: Content blocked - prompt injection detected")
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {
                                "description": f"Content blocked - prompt injection detected: {injection_reason}",
                                "done": True,
                            },
                        }
                    )
                raise ValueError(f"Content blocked - prompt injection detected: {injection_reason}")

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

            is_safe, reason = await self.check_safety(user_content, __user__)
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
                await self.log_violation(__user__, user_content, reason)  # Log to KB
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

            is_safe, reason = await self.check_safety(assistant_content, __user__)
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
                await self.log_violation(
                    __user__, assistant_content, reason
                )  # Log to KB
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
        self, user: Optional[dict], content: str, reason: str
    ) -> None:
        """Log infringement to KB via API."""
        self._dbg_step("Starting log_violation")  # Log entry
        try:
            self._dbg_step("Fetching infringement KB ID")  # Log step
            kb_id = await self._find_knowledge_base_id(self.valves.infringement_kb)
            if not kb_id:
                self._dbg_step(f"Infringement KB not found: {self.valves.infringement_kb}")  # Log missing KB
                return

            entry = {
                "user_id": user.get("id", "unknown") if user else "unknown",
                "datetime": datetime.datetime.now().isoformat(),
                "content": content,
                "reason": reason,
            }
            entry_text = str(entry)
            filename = (
                f"infringement_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            self._dbg_step(f"Preparing to upload file: {filename} with content length {len(entry_text)}")  # Log prep

            form = aiohttp.FormData()
            form.add_field(
                "file", entry_text, filename=filename, content_type="text/plain"
            )
            headers = {
                "Authorization": f"Bearer {self.valves.api_key}",
                "Accept": "application/json",
                "User-Agent": self.valves.user_agent,
            }
            self._dbg_step("Uploading file to /api/v1/files/")  # Log upload start
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.valves.api_url}/api/v1/files/", headers=headers, data=form
                ) as resp:
                    self._dbg_step(f"Upload response status: {resp.status}")  # Log status
                    if resp.status == 429:
                        self._dbg_full("Upload rate limited (429)")
                        return
                    if resp.status == 401:
                        self._dbg_full("Upload unauthorized (401)")
                        return
                    if resp.status == 410:
                        self._dbg_full("Upload endpoint gone (410)")
                        return
                    if resp.status == 200:
                        result = await resp.json()
                        self._dbg_full("Upload response JSON:", result)  # Log full response
                        file_id = result.get("id") or result.get("file_id")
                        if file_id:
                            self._dbg_step("File uploaded, file_id:", self._truncate(str(file_id), 16))
                            associate_url = f"{self.valves.api_url}/api/v1/knowledge/{kb_id}/file/add"
                            data = {
                                "file_id": file_id,
                                "metadata": {"source": "violation_log"},
                            }
                            self._dbg_full("Associating file to KB with data:", data)  # Log association data
                            async with session.post(
                                associate_url, headers=headers, json=data
                            ) as assoc_resp:
                                self._dbg_step(f"Association response status: {assoc_resp.status}")  # Log status
                                if assoc_resp.status == 429:
                                    self._dbg_full("Association rate limited (429)")
                                    return
                                if assoc_resp.status == 401:
                                    self._dbg_full("Association unauthorized (401)")
                                    return
                                if assoc_resp.status == 410:
                                    self._dbg_full("Association endpoint gone (410)")
                                    return
                                if assoc_resp.status != 200:
                                    assoc_text = await assoc_resp.text()
                                    self._dbg_full(f"Association failed: {assoc_text}")  # Log failure details
                        else:
                            self._dbg_step("File uploaded but no file_id returned")  # Log missing ID
                    else:
                        resp_text = await resp.text()
                        self._dbg_full(f"Upload failed: {resp_text}")  # Log failure details
        except Exception as e:
            self._dbg_step(f"Log violation error: {e}")  # Log exception

    async def _get_knowledge_bases(self) -> List[Dict[str, Any]]:
        """Retrieve list of available knowledge bases via API."""
        self._dbg_step("Fetching knowledge bases list")  # Log entry
        headers = {
            "Authorization": f"Bearer {self.valves.api_key}",
            "Content-Type": "application/json",
        }

        list_url = f"{self.valves.api_url}/api/v1/knowledge/list"

        async with aiohttp.ClientSession() as session:
            async with session.get(list_url, headers=headers, timeout=30) as resp:
                self._dbg_step(f"KB list response status: {resp.status}")  # Log status
                if resp.status == 200:
                    result = await resp.json()
                    self._dbg_full("KB list fetched:", result)  # Log result
                    return result
                else:
                    resp_text = await resp.text()
                    self._dbg_full(f"KB list error: {resp_text}")  # Log failure
                    raise Exception(
                        f"Failed to list knowledge bases (HTTP {resp.status})"
                    )

    async def _find_knowledge_base_id(self, kb_name: str) -> Optional[str]:
        """Find knowledge base ID by name via API."""
        self._dbg_step(f"Finding KB ID for: {kb_name}")  # Log entry
        knowledge_bases = await self._get_knowledge_bases()

        for kb in knowledge_bases:
            if kb.get("name") == kb_name:
                kb_id = kb.get("id")
                self._dbg_step("KB found: ID", self._truncate(str(kb_id), 16))  # Log found
                return kb_id

            self._dbg_step(f"KB not found: {kb_name}")  # Log missing KB
        return None

    async def _perform_search(self, kb_id: str, query: str) -> Dict[str, Any]:
        """Perform the actual knowledge base search via API."""
        self._dbg_step(f"Performing search on KB ID {kb_id} with query: {self._truncate(query, 200)}")  # Log entry
        headers = {
            "Authorization": f"Bearer {self.valves.api_key}",
            "Content-Type": "application/json",
        }

        search_url = f"{self.valves.api_url}/api/v1/retrieval/query/collection"
        payload = {
            "collection_names": [kb_id],
            "query": query,
            "k": self.valves.max_results,
            "k_reranker": self.valves.reranker_results,
            "r": self.valves.relevance_threshold,
            "hybrid": self.valves.enable_hybrid_search,
        }
        self._dbg_full("Search payload:", payload)  # Log payload

        async with aiohttp.ClientSession() as session:
            async with session.post(
                search_url, headers=headers, json=payload, timeout=30
            ) as response:
                self._dbg_step(f"Search response status: {response.status}")  # Log status
                if response.status == 200:
                    result = await response.json()
                    self._dbg_full("Search result:", result)  # Log result
                    return result
                else:
                    response_text = await response.text()
                    self._dbg_full(f"KB search error: {self._truncate(response_text, 200)}")  # Log failure details
                    raise Exception(
                        f"Search failed (HTTP {response.status}): {response_text[:200]}"
                    )

    async def _format_results(self, data: Dict[str, Any], kb_name: str) -> str:
        """Format search results for policy snippets."""
        self._dbg_step(f"Formatting results from KB: {kb_name}")  # Log entry
        documents = data.get("documents", [])
        if not documents or not documents[0]:
            self._dbg_step(f"No results from KB: {kb_name}")  # Log empty results
            return ""

        doc_list = documents[0]
        output = ""
        for doc in doc_list:
            output += f"{doc}\n"
        self._dbg_step("Formatted snippets:", self._truncate(output, 200))  # Log formatted (truncated)

        return output.strip()

    async def check_safety(
        self, content: str, user: Optional[dict] = None
    ) -> tuple[bool, str]:
        """
        Check content safety using a safety model via Open WebUI API.
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

            policy_snippets = ""
            if (
                self.valves.compliance_kb
                and self.valves.compliance_kb.lower() != "none"
            ):
                self._dbg_step("Retrieving all policies from compliance KB")  # Log KB retrieval start
                
                # Parse comma-separated KB names
                kb_names = [
                    name.strip()
                    for name in self.valves.compliance_kb.split(",")
                    if name.strip()
                ]
                self._dbg_step("KB names to query:", kb_names)  # Log KB names

                all_snippets = []
                for kb_name in kb_names:
                    try:
                        kb_id = await self._find_knowledge_base_id(kb_name)
                        if not kb_id:
                            self._dbg_step(f"KB ID not found for {kb_name}")  # Log missing ID
                            continue

                        # Retrieve all policies using generic query
                        policy_query = "policy"
                        self._dbg_step(f"Querying KB '{kb_name}' for all policies")  # Log query
                        search_data = await self._perform_search(kb_id, policy_query)
                        kb_snippets = await self._format_results(search_data, kb_name)
                        if kb_snippets:
                            all_snippets.append(kb_snippets)
                    except Exception as e:
                        self._dbg_step(f"KB query error for '{kb_name}': {e}")  # Log per-KB error

                policy_snippets = "\n".join(all_snippets)
                self._dbg_step(f"Retrieved policies: '{self._truncate(policy_snippets, 200)}...'")  # truncated

            # Build prompt (content + policies, no hard-coded instructions)
            prompt = self.build_safety_prompt(sanitized_content, policy_snippets)
            self._dbg_full("Safety prompt:", self._truncate(prompt, 200))  # heavy


            # Resolve safety model ID
            available_models = await self._fetch_available_models()
            safety_model_id = self._resolve_model_id(self.valves.safety_model, available_models)
            self._dbg_step(f"Resolved safety model ID: '{safety_model_id}'")  # Log resolved ID

            # Use Open WebUI's internal API to call the safety model
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": safety_model_id,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                }
                self._dbg_full("Safety payload:", payload)  # heavy

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
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as response:
                    self._dbg_step(f"Safety model response status: {response.status}")  # Log status
                    if response.status != 200:
                        resp_text = await response.text()
                        self._dbg_full(f"Safety model error details: {self._truncate(resp_text, 200)}")  # failure details
                        # Fail-open: do not block due to model transport errors
                        return True, ""  

                    # Read raw response first for debugging
                    resp_text = await response.text()
                    self._dbg_full(f"Raw safety model response: {self._truncate(resp_text, 500)}")

                    # Try to parse JSON
                    try:
                        import json
                        result = json.loads(resp_text) if resp_text else None
                    except json.JSONDecodeError as je:
                        self._dbg_step(f"JSON decode error: {je}")
                        # Fail-open on parse errors
                        return True, ""

                    self._dbg_full("Safety model full result:", result)  # heavy

                    # Validate result structure
                    if not result or not isinstance(result, dict):
                        self._dbg_step(f"Invalid result type: {type(result)}")
                        # Fail-open: treat as safe
                        return True, ""

                    # New: Always expect 'choices' array in result
                    choices = result.get("choices")
                    if not choices or not isinstance(choices, list) or not choices:
                        self._dbg_step("No 'choices' array in model response")
                        # Fail-open: treat as safe
                        return True, ""
                    message = choices[0].get("message", {})
                    response_text = message.get("content", "")

                    # Log the raw response for debugging
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
        - Llama Guard: "safe" or "unsafe\n[category]"
        - Generic: Any response with unsafe/harmful indicators
        """
        self._dbg_step("Parsing safety response:", self._truncate(response_text, 200))  # Log entry
        if not response_text:
            self._dbg_step("Empty safety response - defaulting to safe")  # Log empty response
            return True, ""

        response_lower = response_text.lower().strip()

        # Llama Guard format: starts with "unsafe" on its own line
        if response_lower.startswith("unsafe"):
            lines = response_text.strip().split("\n")
            if len(lines) > 1:
                # Extract category from second line
                category = lines[1].strip()
                # Map Llama Guard categories to detailed explanations
                category_map = {
                    "S1": "Violent Crimes",
                    "S2": "Non-Violent Crimes",
                    "S3": "Sex Crimes",
                    "S4": "Child Exploitation",
                    "S5": "Specialized Advice",
                    "S6": "Privacy",
                    "S7": "Intellectual Property",
                    "S8": "Indiscriminate Weapons",
                    "S9": "Hate",
                    "S10": "Self-Harm",
                    "S11": "Sexual Content",
                }
                detailed_reason = category_map.get(
                    category, category.title() if category else "Harmful Content"
                )
                self._dbg_step(f"Unsafe detected: {detailed_reason}")  # Log detection
                return False, detailed_reason
            self._dbg_step("Unsafe detected: Harmful Content")  # Log
            return False, "Harmful Content"

        # Explicit "safe" response (no "unsafe" modifier)
        if response_lower == "safe" or (
            response_lower.startswith("safe") and "unsafe" not in response_lower
        ):
            self._dbg_step("Safe response")  # Log safe
            return True, ""

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

    async def _fetch_available_models(self) -> List[dict]:
        """Fetch available models from OpenWebUI API to resolve model names to IDs."""
        self._dbg_step("Fetching available models from API")
        headers = {
            "Authorization": f"Bearer {self.valves.api_key}",
            "Accept": "application/json",
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.valves.api_url}/api/v1/models/list",
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30)
                ) as response:
                    self._dbg_step(f"Models list response status: {response.status}")
                    if response.status == 200:
                        data = await response.json()
                        self._dbg_step(f"Models response data type: {type(data)}")
                        self._dbg_full(f"Raw models response: {data}")

                        # Handle multiple response shapes
                        # Open WebUI now returns a dict with 'items' list.
                        if isinstance(data, dict):
                            if "items" in data and isinstance(data["items"], list):
                                models = data["items"]
                            elif "models" in data and isinstance(data["models"], list):
                                models = data["models"]
                            else:
                                self._dbg_step(f"Unexpected models response format keys: {list(data.keys())}")
                                return []
                        elif isinstance(data, list):
                            models = data
                        else:
                            self._dbg_step(f"Unexpected models response type: {type(data)}")
                            return []

                        self._dbg_step(f"Fetched {len(models)} models from API")
                        # Log first few model names for debugging
                        if models:
                            model_names = [m.get('name', m.get('id', 'unknown')) for m in models[:5]]
                            self._dbg_step(f"First few models: {model_names}")
                        return models
                    else:
                        resp_text = await response.text()
                        self._dbg_step(f"Failed to fetch models: {resp_text}")
                        return []
        except Exception as e:
            self._dbg_step(f"Exception fetching models: {e}")
            return []
    
    def _resolve_model_id(self, model_display_name: str, available_models: List[dict]) -> str:
        """Resolve model display name to actual model ID (like pipeline does)."""
        self._dbg_step(f"Resolving model name '{model_display_name}' to ID")
        
        if not model_display_name:
            self._dbg_step("Empty model name provided")
            return ""
        
        # Try to find by display name (name field)
        for model in available_models:
            model_name = model.get("name", "")
            if model_name.lower() == model_display_name.lower():
                model_id = model.get("id", "")
                self._dbg_step(f"Resolved '{model_display_name}' to ID '{model_id}' by name")
                return model_id
        
        # Try by ID directly
        for model in available_models:
            model_id = model.get("id", "")
            if model_id.lower() == model_display_name.lower():
                self._dbg_step(f"Found by ID: '{model_id}'")
                return model_id
        
        # Not found - return original (might already be correct ID)
        self._dbg_step(f"Model '{model_display_name}' not found in {len(available_models)} models - returning original")
        return model_display_name
    
    async def _detect_prompt_injection_semantic(self, content: str) -> tuple[bool, str]:
        """
        PHASE 1: Semantic prompt injection detection using dedicated model.
        NO HARD-CODED PROMPTS. Model's system prompt defines detection logic.
        
        Returns:
            tuple: (is_safe: bool, reason: str)
        """
        self._dbg_step(f"Starting semantic injection detection for content: '{content}'")
        self._dbg_step(f"Using injection detection model: '{self.valves.injection_detection_model}'")
        
        # Fetch and resolve model ID
        available_models = await self._fetch_available_models()
        
        injection_model_id = self._resolve_model_id(self.valves.injection_detection_model, available_models)
        self._dbg_step(f"Resolved injection detection model ID: '{injection_model_id}'")
        # Graceful fallback: if model isn't found, skip semantic detection
        if not injection_model_id or injection_model_id == self.valves.injection_detection_model:
            names = [m.get("name") for m in available_models]
            if self.valves.injection_detection_model not in names:
                self._dbg_step("Injection detection model not available; skipping detection as safe")
                return True, ""
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": injection_model_id,
                    "messages": [{"role": "user", "content": content}],
                    "stream": False,
                }
                headers = {}
                if self.valves.api_key:
                    headers["Authorization"] = f"Bearer {self.valves.api_key}"
                if self.valves.user_agent:
                    headers["User-Agent"] = self.valves.user_agent
                self._dbg_full(f"Querying injection detection model with payload: {str(payload)}")
                async with session.post(
                    f"{self.valves.api_url}/api/v1/chat/completions",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=60),
                ) as response:
                    self._dbg_step(f"Injection detection response status: {response.status}")
                    if response.status == 429:
                        self._dbg_step("Injection detection rate limited (429) - skipping")
                        return True, ""
                    if response.status == 401:
                        self._dbg_step("Injection detection unauthorized (401) - skipping")
                        return True, ""
                    if response.status == 410:
                        self._dbg_step("Injection detection endpoint gone (410) - skipping")
                        return True, ""
                    if response.status != 200:
                        resp_text = await response.text()
                        self._dbg_step(f"Injection detection error: {resp_text}")
                        # Fail-open: do not block on detector transport errors
                        return True, ""
                    resp_text = await response.text()
                    self._dbg_full(f"Raw injection detection response: {self._truncate(resp_text, 500)}")
                    try:
                        import json
                        result = json.loads(resp_text) if resp_text else None
                    except json.JSONDecodeError as je:
                        self._dbg_step(f"Injection detection JSON decode error: {je}")
                        # Fail-open: skip blocking on parse errors
                        return True, ""
                    self._dbg_full(f"Injection detection full result: {str(result)}")
                    if not result or not isinstance(result, dict):
                        self._dbg_step(f"Invalid injection detection result type: {type(result)}")
                        # Fail-open: treat as safe
                        return True, ""
                    choices = result.get("choices")
                    if not choices or not isinstance(choices, list) or not choices:
                        self._dbg_step("No 'choices' array in model response")
                        # Fail-open: treat as safe
                        return True, ""
                    message = choices[0].get("message", {})
                    response_text = message.get("content", "")
                    self._dbg_step(f"Injection detection response: {response_text}")
                    # Strict: Only accept 'SAFE' or 'INJECTION' (case-insensitive)
                    response_clean = response_text.strip().lower()
                    if response_clean == "safe":
                        return True, ""
                    if response_clean == "injection":
                        return False, "Prompt Injection Detected"
                    # Any other output: fail-open
                    return True, ""
        except Exception as e:
            self._dbg_step(f"Injection detection exception: {e}")
            # Fail-open: do not block on unexpected exceptions
            return True, ""

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
