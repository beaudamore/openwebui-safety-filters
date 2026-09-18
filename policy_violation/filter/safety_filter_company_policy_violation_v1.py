"""
Policy Violation Filter for Open WebUI
Filters user inputs for potential company policy violations using local Open WebUI libraries (internal chat + vector DB) with optional policy augmentation.
All remote HTTP API usage removed; only explicit policy violation detection remains.
version: 1.1.0
requirements: pydantic
openwebui: 0.11.3 (verified 2026-09-12, image ghcr.io/open-webui/open-webui:main @ 0a7c158)
"""

from typing import Optional, Callable, Awaitable, List, Any
from pydantic import BaseModel, Field
import asyncio
import json
import unicodedata
import datetime  # For datetime logging
import inspect
from tempfile import SpooledTemporaryFile


SAFETY_TAXONOMY = """S1: Violence.
S2: Sexual.
S3: Criminal Planning/Confessions.
S4: Guns and Illegal Weapons.
S5: Controlled/Regulated Substances.
S6: Suicide and Self Harm.
S7: Sexual (minor).
S8: Hate/Identity Hate.
S9: PII/Privacy.
S10: Harassment.
S11: Threat.
S12: Profanity.
S13: Needs Caution.
S14: Other.
S15: Manipulation.
S16: Fraud/Deception.
S17: Malware.
S18: High Risk Gov Decision Making.
S19: Political/Misinformation/Conspiracy.
S20: Copyright/Trademark/Plagiarism.
S21: Unauthorized Advice.
S22: Illegal Activity.
S23: Immoral/Unethical."""

# Exact code -> name lookup built from the taxonomy above (e.g. "S22" -> "Illegal Activity").
TAXONOMY_BY_CODE = {
    line.split(":", 1)[0].strip(): line.split(":", 1)[1].strip().rstrip(".")
    for line in SAFETY_TAXONOMY.splitlines()
    if ":" in line
}


def categories_to_names(categories: str) -> str:
    """Map the classifier's comma-separated categories to taxonomy names.

    Accepts codes ("S22"), code-prefixed labels ("S22: Illegal Activity") or bare names.
    Uses exact code matching so "S22" never resolves to "S2". Unknown entries are dropped,
    duplicates removed, order preserved. Returns all applicable names joined by ", ".
    """
    names_set = set(TAXONOMY_BY_CODE.values())
    names = []
    for raw in str(categories or "").split(","):
        item = raw.strip().rstrip(".")
        if not item:
            continue
        code = item.split(":", 1)[0].strip()
        name = TAXONOMY_BY_CODE.get(code)
        if name is None and item in names_set:
            name = item
        if name and name not in names:
            names.append(name)
    return ", ".join(names)

# Local Open WebUI imports (guarded for environments outside runtime)
try:
    from open_webui.utils.chat import generate_chat_completion  # type: ignore
    from open_webui.models.knowledge import Knowledges, KnowledgeForm  # type: ignore
    from open_webui.models.users import Users  # type: ignore
    from open_webui.retrieval.vector.factory import VECTOR_DB_CLIENT  # type: ignore
    from open_webui.routers.files import upload_file_handler  # type: ignore
    from fastapi import UploadFile  # type: ignore
    from fastapi.concurrency import run_in_threadpool  # type: ignore
except ImportError:  # pragma: no cover - guarded optional runtime deps
    generate_chat_completion = None
    Knowledges = None
    KnowledgeForm = None
    Users = None
    VECTOR_DB_CLIENT = None
    upload_file_handler = None
    UploadFile = None
    run_in_threadpool = None


async def _call_openwebui(func, *args, **kwargs):
    if inspect.iscoroutinefunction(func):
        return await func(*args, **kwargs)
    if run_in_threadpool:
        result = await run_in_threadpool(func, *args, **kwargs)
    else:
        result = func(*args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result


FILTER_BLOCK_AWARE = True  # this filter records blocks in the shared record and defers to later block-aware filters

try:
    from open_webui.utils.filter import resolve_filter_pipeline  # type: ignore
    from open_webui.utils.plugin import get_function_module_from_cache  # type: ignore
except ImportError:  # pragma: no cover
    resolve_filter_pipeline = None
    get_function_module_from_cache = None


class Filter:
    """
    Open WebUI Filter implementation for content Policy Violation.
    """

    # Also on the class: Open WebUI's function cache hands back the Filter instance, not the module.
    FILTER_BLOCK_AWARE = True

    class Valves(BaseModel):
        priority: int = 0
        enabled: bool = True
        policy_model_id: str = Field(
            default="prompt-safety-and-policy-violation-detector",
            description="Direct model ID for policy violation classification (internal).",
        )
        block_on_unsafe: bool = True
        block_mode: str = Field(
            default="message",
            description="'message': show block_message as the reply and end the turn without calling the model, so the chat stays usable. 'error': raise an error on the message (old behaviour).",
        )
        block_message: str = Field(
            default="⛔ This message was blocked by a safety filter and was not sent to the model. You can continue the conversation.",
            description="Static text shown as the assistant reply when a prompt is blocked (block_mode='message').",
        )
        enable_full_debug: bool = Field(
            default=False,
            description="Enable heavy debugging logs, including payloads/results (masked & truncated).",
        )
        enable_step_debug: bool = Field(
            default=False,
            description="Enable step-by-step progress logs (concise, truncated).",
        )
        compliance_kb: str = Field(
            default="Company Policies",
            description="Comma-separated knowledge base name(s) used to augment violation checks. 'none' disables augmentation.",
        )
        violation_kb: str = Field(
            default="Company Policy Violations",
            description="Knowledge base name for logging violations. Created automatically if missing.",
        )
        max_docs_per_kb: int = Field(
            default=50,
            description="Maximum documents pulled per KB for prompt augmentation.",
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
        except (ValueError, TypeError):
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
        except (OSError, TypeError, ValueError):
            # Best-effort: avoid crashing due to logging
            pass

    def _dbg_step(self, *parts: Any) -> None:
        if self._is_step_debug():
            self._print_safely(*parts)

    def _dbg_full(self, *parts: Any) -> None:
        if self._is_full_debug():
            self._print_safely(*parts)

    async def _block_turn(self, __event_emitter__, body: Optional[dict] = None) -> None:
        """Show the static block message plus every recorded reason as the reply and end the
        turn without calling the model."""
        record = ((body or {}).get("metadata") or {}).get("filter_block") or {}
        reasons = [str(r) for r in record.get("reasons", []) if r]
        text = self.valves.block_message
        if reasons:
            text += "\n\n" + "\n".join(f"- {r[:1].upper()}{r[1:]}" for r in reasons)
        if __event_emitter__:
            await __event_emitter__({"type": "replace", "data": {"content": text}})
        raise asyncio.CancelledError("blocked by filter")

    def _record_block(self, body: dict, reason: str) -> None:
        """Record a violation in the shared block record (request metadata, never sent to the model).
        The prompt is left untouched so later filters scan the same original text."""
        meta = body.setdefault("metadata", {})
        record = meta.setdefault("filter_block", {"reasons": []})
        record.setdefault("reasons", []).append(reason)
        self._dbg_step(f"Block recorded: {reason}")

    async def _enforce_block_if_last(
        self, body, __event_emitter__, __request__, __model__, __metadata__, __id__
    ) -> None:
        """If anything was recorded and no later block-aware filter will run, show the static
        block message and end the turn. If the chain cannot be resolved, block immediately."""
        record = (body.get("metadata") or {}).get("filter_block")
        if not record or not record.get("reasons"):
            return
        try:
            if not (resolve_filter_pipeline and get_function_module_from_cache and __request__ and __model__):
                raise RuntimeError("filter chain helpers unavailable")
            enabled_ids = (__metadata__ or body.get("metadata") or {}).get("filter_ids", []) or []
            chain, _ = await resolve_filter_pipeline(__request__, __model__, enabled_ids)
            later = chain[chain.index(__id__) + 1 :] if __id__ in chain else []
            for fid in later:
                module, _, _ = await get_function_module_from_cache(__request__, fid)
                if getattr(module, "FILTER_BLOCK_AWARE", False):
                    self._dbg_step(f"Block recorded; deferring final block to later filter '{fid}'")
                    return
        except Exception as e:
            self._dbg_step(f"Could not resolve filter chain ({e}); blocking now")
        await self._block_turn(__event_emitter__, body)

    def _scrub_blocked_history(self, messages: list) -> list:
        """Drop earlier blocked user messages and their block replies so blocked content never reaches the model as history."""
        blocked = self.valves.block_message.strip()
        out: list = []
        for m in messages:
            content = m.get("content", "")
            if (
                m.get("role") == "assistant"
                and isinstance(content, str)
                and content.strip().startswith(blocked)
            ):
                if out and out[-1].get("role") == "user":
                    out.pop()
                continue
            out.append(m)
        return out

    def _status_text(self, is_violation: bool, reason: str) -> str:
        """Status line for the UI. A failed check must not read as a pass."""
        if is_violation:
            return f"Policy check complete: ⚠ {reason} detected"
        if reason:
            return f"Policy check FAILED (not enforced): {reason}"
        return "Policy check complete: ✓ No violation"

    async def _generate_policy_completion(
        self,
        request: Optional[Any],
        payload: dict,
        user: Optional[dict],
    ) -> Any:
        if not request or not hasattr(request, "state"):
            return await generate_chat_completion(
                request=request,
                form_data=payload,
                user=user,
                bypass_filter=True,
            )

        had_bypass_filter = hasattr(request.state, "bypass_filter")
        previous_bypass_filter = getattr(request.state, "bypass_filter", None)
        had_bypass_system_prompt = hasattr(request.state, "bypass_system_prompt")
        previous_bypass_system_prompt = getattr(request.state, "bypass_system_prompt", None)

        try:
            return await generate_chat_completion(
                request=request,
                form_data=payload,
                user=user,
                bypass_filter=True,
            )
        finally:
            if had_bypass_filter:
                request.state.bypass_filter = previous_bypass_filter
            elif hasattr(request.state, "bypass_filter"):
                delattr(request.state, "bypass_filter")

            if had_bypass_system_prompt:
                request.state.bypass_system_prompt = previous_bypass_system_prompt
            elif hasattr(request.state, "bypass_system_prompt"):
                delattr(request.state, "bypass_system_prompt")

    async def _get_or_create_knowledge_id(self, user_id: str, kb_name: str) -> Optional[str]:
        if not all([Knowledges, KnowledgeForm]):
            self._dbg_step("Knowledge modules unavailable")
            return None

        # the per-user knowledge lookup was removed from Open WebUI; list all and match by id or name
        kbs = await _call_openwebui(Knowledges.get_knowledge_bases)
        if kbs:
            for kb in kbs:
                if kb.id == kb_name or kb.name == kb_name:
                    return kb.id

        knowledge_form = KnowledgeForm(
            name=kb_name,
            description="Auto-created by Policy Violation Filter",
            data={},
        )
        new_kb = await _call_openwebui(
            Knowledges.insert_new_knowledge,
            user_id,
            knowledge_form,
        )
        if not new_kb:
            self._dbg_step(f"Failed to create KB '{kb_name}'")
            return None
        self._dbg_step(f"Created KB '{kb_name}' (ID: {new_kb.id})")
        return new_kb.id

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
        __model__: Optional[dict] = None,
        __metadata__: Optional[dict] = None,
        __id__: Optional[str] = None,
    ) -> dict:
        body = await self._inlet_impl(
            body,
            __user__=__user__,
            __event_emitter__=__event_emitter__,
            __request__=__request__,
        )
        await self._enforce_block_if_last(
            body, __event_emitter__, __request__, __model__, __metadata__, __id__
        )
        return body

    async def _inlet_impl(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        """
        Filter incoming user messages for company policy violations.
        """
        self._dbg_full("Inlet called with body:", body)  # heavy: full body
        if not self.valves.enabled:
            self._dbg_step("Inlet skipped: Disabled")  # Log skip
            return body

        messages = self._scrub_blocked_history(body.get("messages", []))
        body["messages"] = messages
        if not messages:
            self._dbg_step("Inlet skipped: No messages")  # Log skip
            return body

        # Check the last user message
        last_message = messages[-1]
        if last_message.get("role") == "user":
            user_content = last_message.get("content", "")
            self._dbg_step("Checking user content:", self._truncate(user_content, 100))

            if __event_emitter__:
                self._dbg_step("Emitting status: Checking for policy violations...")  # Log emit
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Checking content Policy Violation...",
                            "done": False,
                        },
                    }
                )

            is_violation, reason = await self.check_policy_violation(user_content, __user__, __request__, check_response=False)
            self._dbg_step(f"Policy violation check result: is_violation={is_violation} reason={reason}")

            if __event_emitter__:
                self._dbg_step("Emitting status: Policy violation check complete")  # Log emit
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": self._status_text(is_violation, reason),
                            "done": True,
                        },
                    }
                )

            if is_violation and self.valves.block_on_unsafe:
                await self.log_violation(__user__, user_content, reason, __request__)  # Log to KB
                self._dbg_step(f"Blocking input content due to policy violation: {reason}")
                self._dbg_full("Blocking input content payload:", user_content)
                if __event_emitter__:
                    self._dbg_step("Emitting status: Content blocked by policy violation filter")  # Log emit
                    await __event_emitter__(
                        {
                            "type": "status",
                            "data": {
                                "description": "Content blocked: policy violation",
                                "done": True,
                            },
                        }
                    )
                if self.valves.block_mode == "error":
                    raise ValueError(f"Content blocked due to policy violation: {reason}")
                self._record_block(body, f"policy violation: {reason}")
                return body

        return body

    async def log_violation(
        self, user: Optional[dict], content: str, reason: str, request: Optional[Any] = None
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

        if not all([upload_file_handler, Knowledges, KnowledgeForm, Users, UploadFile]):
            self._dbg_step("Required OpenWebUI modules not available for KB logging")
            return

        if not request or not user:
            self._dbg_step("Missing request or user context for KB logging")
            return

        try:
            # Resolve User object
            user_obj = await _call_openwebui(Users.get_user_by_id, str(user["id"]))
            if not user_obj:
                self._dbg_step("Could not resolve User object")
                return

            # Find KB by name; create it if it doesn't exist.
            kb_name = self.valves.violation_kb.strip()
            kb_id = await self._get_or_create_knowledge_id(user_obj.id, kb_name)
            if not kb_id:
                return

            # Prepare content
            full_log_content = (
                f"--- Policy Violation Report ---\n"
                f"Timestamp: {timestamp}\n"
                f"User ID: {user.get('id', 'unknown')}\n"
                f"User Name: {user.get('name', 'unknown')}\n"
                f"User Email: {user.get('email', 'unknown')}\n"
                f"Reason: {reason}\n"
                f"--- Content ---\n"
                f"{content}\n"
                f"-------------------------------\n"
            )

            filename = f"violation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
            # Upload File
            upload = UploadFile(
                filename=filename,
                file=SpooledTemporaryFile(max_size=1024 * 1024),
                headers={"content-type": "text/plain"},
            )
            upload.file.write(full_log_content.encode("utf-8"))
            upload.file.seek(0)

            try:
                file_data = await _call_openwebui(
                    upload_file_handler,
                    request,
                    upload,
                    {"source": "policy_filter", "type": "violation_report", "knowledge_id": kb_id}, # metadata
                    True, # process
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

            self._dbg_step(f"Violation logged to KB '{kb_name}' (File ID: {file_id})")

        except Exception as e:
            self._dbg_step(f"Error logging violation to KB: {e}")

    # Remote KB helper methods removed; using local vector DB client.

    async def check_policy_violation(
        self,
        content: str,
        user: Optional[dict] = None,
        __request__: Optional[Any] = None,
        check_response: bool = False,
    ) -> tuple[bool, str]:
        """
        Check content for company policy violations using the configured model
        and optional compliance knowledge bases. Harm/violence categories have
        been removed; only explicit policy violations are flagged.

        Returns:
            tuple: (is_violation: bool, reason: str)
        """
        try:
            self._dbg_step(f"Starting policy violation check for content: '{self._truncate(content, 100)}...'")  # start
            # Sanitize: Remove all Unicode controls, preserve multilingual chars
            sanitized_content = "".join(
                c for c in content if not unicodedata.category(c).startswith("C")
            )
            self._dbg_step("Sanitized content:", self._truncate(sanitized_content, 100))  # Log sanitized

            policy_snippets = ""
            ckb = str(self.valves.compliance_kb)
            if ckb and ckb.lower() != "none":
                kb_names = [n.strip() for n in ckb.split(",") if n.strip()]
                self._dbg_step("Local KB names:", kb_names)
                snippets: List[str] = []
                user_obj = None
                if user and Users:
                    try:
                        user_obj = await _call_openwebui(Users.get_user_by_id, str(user["id"]))
                    except (KeyError, AttributeError, RuntimeError, ValueError) as e:
                        self._dbg_step(f"Failed to resolve user for compliance KB creation: {e}")
                for kb_name in kb_names:
                    kb_id = None
                    if user_obj:
                        try:
                            kb_id = await self._get_or_create_knowledge_id(user_obj.id, kb_name)
                        except (AttributeError, RuntimeError, ValueError) as e:
                            self._dbg_step(f"Failed to create or resolve KB '{kb_name}': {e}")
                    if not kb_id:
                        self._dbg_step(f"KB not found or created: {kb_name}")
                        continue
                    if not VECTOR_DB_CLIENT:
                        self._dbg_step("VECTOR_DB_CLIENT unavailable; skipping")
                        continue
                    try:
                        if hasattr(VECTOR_DB_CLIENT, "has_collection") and not VECTOR_DB_CLIENT.has_collection(kb_id):
                            self._dbg_step(f"KB '{kb_name}' has no vector collection yet; skipping")
                            continue
                        result = VECTOR_DB_CLIENT.get(collection_name=kb_id)
                        if result and result.documents and result.documents[0]:
                            docs = result.documents[0][: self.valves.max_docs_per_kb]
                            snippets.append("\n".join(docs))
                            self._dbg_step(f"Collected {len(docs)} docs from '{kb_name}'")
                        else:
                            self._dbg_step(f"No documents in KB '{kb_name}'")
                    except (RuntimeError, ValueError) as e:
                        self._dbg_step(f"Error reading KB '{kb_name}': {e}")
                policy_snippets = "\n".join(snippets)
                self._dbg_step("Aggregated policy snippet length:", len(policy_snippets))

            prompt = self.build_violation_prompt(sanitized_content, policy_snippets, check_response=check_response)
            self._dbg_full("Policy violation prompt:", self._truncate(prompt, 200))  # heavy


            # Invoke local model (internal library)
            if not generate_chat_completion:
                self._dbg_step("generate_chat_completion unavailable; treating as no violation")
                return False, "check failed: generate_chat_completion unavailable"
            payload = {
                "model": self.valves.policy_model_id,
                "messages": [{"role": "user", "content": prompt}],
                "stream": False,
            }
            self._dbg_full("Local policy violation payload:", payload)
            try:
                response = await self._generate_policy_completion(__request__, payload, user)
            except Exception as e:
                self._dbg_step(f"Model invocation error: {e}; no violation")
                return False, f"check failed: model error: {e}"
            if isinstance(response, dict):
                choices = response.get("choices", [])
                if choices and isinstance(choices, list):
                    message = choices[0].get("message", {})
                    response_text = message.get("content", "")
                else:
                    self._dbg_step("Empty choices; no violation")
                    return False, "check failed: empty model response"
            else:
                self._dbg_step(f"Unexpected response type {type(response)}; no violation")
                return False, f"check failed: unexpected response type {type(response).__name__}"
            self._dbg_step("Policy model text response:", self._truncate(response_text, 200))
            return self._parse_violation_response(response_text, check_response=check_response)

        except Exception as e:
            self._dbg_step(f"Policy violation check exception: {e}")
            return False, f"check failed: {e}"  # Fail-open -> no violation, but reported

    def _parse_violation_response(self, response_text: str, check_response: bool = False) -> tuple[bool, str]:
        """
        Parse the Qwen safety LoRA structured JSON response.
        """
        self._dbg_step("Parsing policy violation response:", self._truncate(response_text, 200))  # Log entry
        if not response_text:
            self._dbg_step("Empty policy response - defaulting to no violation")  # Log empty response
            return False, "check failed: empty model response"

        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.strip("`").strip()
            if cleaned.lower().startswith("json"):
                cleaned = cleaned[4:].strip()

        try:
            parsed = json.loads(cleaned)
        except (json.JSONDecodeError, TypeError) as e:
            self._dbg_step(f"Invalid policy JSON response: {e}")
            return False, f"check failed: invalid JSON from model: {e}"

        safety_key = "Response Safety" if check_response else "User Safety"
        safety_value = str(parsed.get(safety_key, "")).strip().lower()
        if safety_value != "unsafe":
            self._dbg_step(f"{safety_key} is not unsafe")
            return False, ""

        categories = str(parsed.get("Safety Categories", "")).strip()
        reason = categories_to_names(categories) or categories or "Policy Violation"
        self._dbg_step(f"Unsafe content detected: {reason}")
        return True, reason

        # Default to safe if no unsafe indicators found
        self._dbg_step("Defaulting to safe: No indicators found")  # Log default
        return False, ""

    # Remote model resolution helpers removed; direct model ID provided in valves.
    

    def build_violation_prompt(self, content: str, policy_snippets: str = "", check_response: bool = False) -> str:
        """
        Build the classifier prompt in the format used to train the Qwen safety LoRA.
        """
        self._dbg_step("Building policy violation prompt")  # Log entry

        taxonomy = SAFETY_TAXONOMY
        if policy_snippets:
            taxonomy = f"{taxonomy}\n\nCompany Policies:\n{policy_snippets}"

        if check_response:
            conversation = f"\nuser: <no user message provided>\nresponse: agent: {content}"
        else:
            conversation = f"\nuser: {content}"

        return f"""Task: Check if there is unsafe content in the user or agent messages in the below conversation in accordance with our safety policy with the below categories. Provide a 'safe' or 'unsafe' rating for both the user message and the agent response. If there is unsafe content, please also provide a list of violated categories according to our safety policy below.

<BEGIN UNSAFE CONTENT CATEGORIES>
{taxonomy}
<END UNSAFE CONTENT CATEGORIES>

<BEGIN CONVERSATION>
{conversation}
<END CONVERSATION>

Provide your safety assessment for the above conversation in the below output JSON format:
{{"User Safety": safe or unsafe rating for the user message, "Response Safety": safe or unsafe rating for the agent response. Omit if no agent response present. "Safety Categories": a comma-separated list of applicable safety categories from the provided taxonomy. Omit if all safe.}}

Do not include anything other than the output JSON in your response.
Output JSON:"""
