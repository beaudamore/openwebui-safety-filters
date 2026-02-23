"""
title: Safety Guard Filter v3 (Nemotron Classifier)
author: spark
version: 3.0.0
requirements: pydantic
description: Nemotron-style 23-category safety classifier filter for Qwen3-14B Safety Guard LoRA
"""

import json
import re
import logging
import datetime
from typing import Optional, Callable, Awaitable, Any
from tempfile import SpooledTemporaryFile
from pydantic import BaseModel, Field

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

logger = logging.getLogger(__name__)


# ─── Full 23-category Aegis 2.0 / Nemotron taxonomy ─────────────────────────
SAFETY_TAXONOMY = {
    "S1": "Violence",
    "S2": "Sexual",
    "S3": "Criminal Planning/Confessions",
    "S4": "Guns and Illegal Weapons",
    "S5": "Controlled/Regulated Substances",
    "S6": "Suicide and Self Harm",
    "S7": "Sexual (minor)",
    "S8": "Hate/Identity Hate",
    "S9": "PII/Privacy",
    "S10": "Harassment",
    "S11": "Threat",
    "S12": "Profanity",
    "S13": "Needs Caution",
    "S14": "Other",
    "S15": "Manipulation",
    "S16": "Fraud/Deception",
    "S17": "Malware",
    "S18": "High Risk Gov Decision Making",
    "S19": "Political/Misinformation/Conspiracy",
    "S20": "Copyright/Trademark/Plagiarism",
    "S21": "Unauthorized Advice",
    "S22": "Illegal Activity",
    "S23": "Immoral/Unethical",
}


class Filter:
    """
    Nemotron-style safety classifier filter for OpenWebUI.
    
    Inlet:  checks user message before it reaches the main model.
    Outlet: checks assistant response before it's shown to the user.
    """

    class Valves(BaseModel):
        priority: int = Field(
            default=-1,
            description="Filter priority (lower runs first; -1 ensures safety runs before other filters)"
        )

        # --- Model ---
        safety_model_id: str = Field(
            default="safety-guard-qwen3-14b",
            description="OpenWebUI model ID for the safety guard LoRA"
        )

        # --- Behavior ---
        block_on_unsafe: bool = Field(
            default=True,
            description="Block unsafe content (True) or just log it (False)"
        )
        check_input: bool = Field(
            default=True,
            description="Run safety check on user input (inlet)"
        )
        check_output: bool = Field(
            default=True,
            description="Run safety check on assistant output (outlet)"
        )
        unsafe_message: str = Field(
            default="I'm unable to process this request as it may involve unsafe content.",
            description="Message shown to user when content is blocked"
        )

        # --- Category toggles (all enabled by default) ---
        # Set any to False to ignore that category during classification
        S1_Violence: bool = Field(default=True)
        S2_Sexual: bool = Field(default=True)
        S3_Criminal_Planning: bool = Field(default=True)
        S4_Guns_Illegal_Weapons: bool = Field(default=True)
        S5_Controlled_Substances: bool = Field(default=True)
        S6_Suicide_Self_Harm: bool = Field(default=True)
        S7_Sexual_Minor: bool = Field(default=True)
        S8_Hate_Identity: bool = Field(default=True)
        S9_PII_Privacy: bool = Field(default=True)
        S10_Harassment: bool = Field(default=True)
        S11_Threat: bool = Field(default=True)
        S12_Profanity: bool = Field(default=False, description="Disabled by default — too aggressive for casual chat")
        S13_Needs_Caution: bool = Field(default=False, description="Disabled by default — advisory only")
        S14_Other: bool = Field(default=False, description="Disabled by default — catch-all")
        S15_Manipulation: bool = Field(default=True)
        S16_Fraud_Deception: bool = Field(default=True)
        S17_Malware: bool = Field(default=True)
        S18_High_Risk_Gov: bool = Field(default=True)
        S19_Political_Misinfo: bool = Field(default=True)
        S20_Copyright: bool = Field(default=True)
        S21_Unauthorized_Advice: bool = Field(default=True)
        S22_Illegal_Activity: bool = Field(default=True)
        S23_Immoral_Unethical: bool = Field(default=True)

        # --- Logging ---
        violation_kb: str = Field(
            default="",
            description="Knowledge Base collection name to log violations to (leave empty to disable)"
        )
        enable_full_debug: bool = Field(
            default=False,
            description="Log full prompts and responses at DEBUG level"
        )
        enable_step_debug: bool = Field(
            default=False,
            description="Log step-by-step filter processing at INFO level"
        )

    def __init__(self):
        self.valves = self.Valves()
        # Map valve field names back to taxonomy codes
        self._valve_to_code = {
            "S1_Violence": "S1",
            "S2_Sexual": "S2",
            "S3_Criminal_Planning": "S3",
            "S4_Guns_Illegal_Weapons": "S4",
            "S5_Controlled_Substances": "S5",
            "S6_Suicide_Self_Harm": "S6",
            "S7_Sexual_Minor": "S7",
            "S8_Hate_Identity": "S8",
            "S9_PII_Privacy": "S9",
            "S10_Harassment": "S10",
            "S11_Threat": "S11",
            "S12_Profanity": "S12",
            "S13_Needs_Caution": "S13",
            "S14_Other": "S14",
            "S15_Manipulation": "S15",
            "S16_Fraud_Deception": "S16",
            "S17_Malware": "S17",
            "S18_High_Risk_Gov": "S18",
            "S19_Political_Misinfo": "S19",
            "S20_Copyright": "S20",
            "S21_Unauthorized_Advice": "S21",
            "S22_Illegal_Activity": "S22",
            "S23_Immoral_Unethical": "S23",
        }

    # ─── Taxonomy builder (respects valve toggles) ───────────────────────────

    def _get_enabled_categories(self) -> dict[str, str]:
        """Return only the taxonomy categories that are enabled via valves."""
        enabled = {}
        for valve_name, code in self._valve_to_code.items():
            if getattr(self.valves, valve_name, True):
                enabled[code] = SAFETY_TAXONOMY[code]
        return enabled

    def _build_taxonomy_text(self, enabled: dict[str, str]) -> str:
        """Build the taxonomy block for the classifier prompt."""
        lines = [f"{code}: {name}." for code, name in enabled.items()]
        return "\n".join(lines)

    # ─── Classifier prompt builder ───────────────────────────────────────────

    def _build_classifier_prompt(
        self,
        user_message: str,
        agent_response: Optional[str] = None,
    ) -> str:
        """
        Build the full Nemotron-style classifier prompt as the USER message.

        This reproduces the EXACT format the LoRA was trained with:
        1. Task instruction with safety policy
        2. Taxonomy of enabled categories
        3. Conversation wrapped in <BEGIN/END CONVERSATION> tags
        4. JSON output instruction

        Everything goes as the user message — no system prompt needed.
        """
        # Build taxonomy block from enabled categories only
        enabled = self._get_enabled_categories()
        taxonomy_text = self._build_taxonomy_text(enabled)

        # Build conversation block
        conversation = f"\nuser: {user_message}"
        if agent_response:
            conversation += f"\nresponse: agent: {agent_response}"

        return (
            f"Task: Check if there is unsafe content in the user or agent messages "
            f"in the below conversation in accordance with our safety policy with the "
            f"below categories. Provide a 'safe' or 'unsafe' rating for both the user "
            f"message and the agent response. If there is unsafe content, please also "
            f"provide a list of violated categories according to our safety policy below."
            f"\n\n<BEGIN UNSAFE CONTENT CATEGORIES>"
            f"\n{taxonomy_text}"
            f"\n<END UNSAFE CONTENT CATEGORIES>"
            f"\n\n<BEGIN CONVERSATION>"
            f"\n{conversation}"
            f"\n<END CONVERSATION>"
            f"\n\nProvide your safety assessment for the above conversation "
            f"in the below output JSON format:"
            f'\n{{"User Safety": safe or unsafe rating for the user message, '
            f'"Response Safety": safe or unsafe rating for the agent response. '
            f'Omit if no agent response present. '
            f'"Safety Categories": a comma-separated list of applicable safety '
            f"categories from the provided taxonomy. Omit if all safe.}}"
            f"\n\nDo not include anything other than the output JSON in your response."
            f"\nOutput JSON: "
        )

    # ─── Response parser ─────────────────────────────────────────────────────

    def _parse_safety_response(self, raw: str) -> dict:
        """
        Parse the classifier's JSON output.

        Expected JSON format (matches LoRA training output):
            {"User Safety": "safe"}
            {"User Safety": "unsafe", "Safety Categories": "Violence,Threat"}
            {"User Safety": "unsafe", "Response Safety": "unsafe", "Safety Categories": "Sexual"}

        Returns a normalized dict with keys:
            - user_safe: bool
            - response_safe: bool | None
            - categories: list[str]  (full taxonomy names like "Violence", not codes)
            - raw: str
        """
        result = {
            "user_safe": True,
            "response_safe": None,
            "categories": [],
            "raw": raw.strip(),
        }

        if not raw or not raw.strip():
            logger.warning("[SafetyGuard] Empty safety response — defaulting to safe")
            return result

        # Clean the raw output — strip thinking tags, whitespace
        cleaned = raw.strip()
        cleaned = re.sub(r"<think>.*?</think>", "", cleaned, flags=re.DOTALL).strip()

        # Remove markdown code fences if present
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```(?:\w+)?\s*", "", cleaned)
            cleaned = re.sub(r"\s*```$", "", cleaned)
            cleaned = cleaned.strip()

        # Try to parse as JSON first (primary path — matches LoRA training format)
        try:
            # Handle case where model outputs "Output JSON: {...}" prefix
            json_match = re.search(r'\{.*\}', cleaned, flags=re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(cleaned)

            # Parse "User Safety" field
            user_safety = data.get("User Safety", "safe").strip().lower()
            result["user_safe"] = user_safety == "safe"

            # Parse "Response Safety" field (may be absent)
            if "Response Safety" in data:
                resp_safety = data["Response Safety"].strip().lower()
                result["response_safe"] = resp_safety == "safe"

            # Parse "Safety Categories" field (comma-separated taxonomy names)
            if "Safety Categories" in data and data["Safety Categories"]:
                cats_str = data["Safety Categories"]
                result["categories"] = [
                    c.strip() for c in cats_str.split(",") if c.strip()
                ]

            return result

        except (json.JSONDecodeError, AttributeError, TypeError):
            # JSON parse failed — fall back to text heuristics
            logger.warning(f"[SafetyGuard] JSON parse failed, trying text fallback: {cleaned[:200]}")

        # Fallback: plain text heuristics (handles degraded model output)
        response_lower = cleaned.lower().strip()

        if response_lower == "safe" or (
            response_lower.startswith("safe") and "unsafe" not in response_lower
        ):
            return result

        if "unsafe" in response_lower:
            result["user_safe"] = False
            # Try to extract category names from the text
            for code, name in SAFETY_TAXONOMY.items():
                if name.lower() in response_lower:
                    result["categories"].append(name)
            if not result["categories"]:
                result["categories"] = ["Harmful Content"]
            return result

        # Default to safe if nothing recognizable
        return result

    # ─── Category filtering (apply valve toggles to model output) ────────────

    def _filter_categories(self, categories: list[str]) -> list[str]:
        """
        Remove any reported categories that are disabled in valves.
        This allows the model to still classify them, but we ignore them at runtime.
        """
        enabled = self._get_enabled_categories()
        enabled_names = set(enabled.values())

        filtered = []
        for cat in categories:
            # Match by full name
            if cat in enabled_names:
                filtered.append(cat)
            else:
                # Try matching by code prefix (e.g., "S7" in "S7: Sexual (minor)")
                for code, name in enabled.items():
                    if cat.startswith(code) or name.startswith(cat):
                        filtered.append(name)
                        break
        return filtered

    # ─── Safety check (shared by inlet/outlet) ──────────────────────────────
    # Copied from v2's check_safety — identical flow, only prompt + parser differ.

    async def _check_safety(
        self,
        user_message: str,
        agent_response: Optional[str],
        __user__: dict,
        __request__,
    ) -> dict:
        """
        Run the safety classifier. Identical call pattern to v2's check_safety.
        """
        try:
            classifier_prompt = self._build_classifier_prompt(user_message, agent_response)

            if self.valves.enable_full_debug:
                logger.debug(f"[SafetyGuard] Classifier prompt:\n{classifier_prompt}")

            payload = {
                "model": self.valves.safety_model_id,
                "messages": [
                    {"role": "user", "content": classifier_prompt}
                ],
                "stream": False,
            }

            response = await generate_chat_completion(
                request=__request__,
                form_data=payload,
                user=__user__,
                bypass_filter=True,
            )

            if isinstance(response, dict):
                choices = response.get("choices", [])
                if not choices or not isinstance(choices, list):
                    logger.warning("[SafetyGuard] No 'choices' in model response")
                    return {"user_safe": True, "response_safe": None, "categories": [], "raw": ""}
                message = choices[0].get("message", {})
                raw_output = message.get("content", "")
            else:
                logger.warning(f"[SafetyGuard] Unexpected response type: {type(response)}")
                return {"user_safe": True, "response_safe": None, "categories": [], "raw": ""}

            if self.valves.enable_full_debug:
                logger.debug(f"[SafetyGuard] Raw model output: {raw_output}")

            result = self._parse_safety_response(raw_output)

            # Apply category toggles — ignore disabled categories
            if result["categories"]:
                result["categories"] = self._filter_categories(result["categories"])
                if not result["categories"]:
                    result["user_safe"] = True
                    result["response_safe"] = True if result["response_safe"] is not None else None

            if self.valves.enable_step_debug:
                logger.info(f"[SafetyGuard] Result: user_safe={result['user_safe']}, "
                           f"response_safe={result['response_safe']}, "
                           f"categories={result['categories']}")

            return result

        except Exception as e:
            logger.error(f"[SafetyGuard] Safety check exception: {e}")
            # Fail-open: same as v2
            return {"user_safe": True, "response_safe": None, "categories": [], "raw": f"ERROR: {e}"}

    # ─── Violation logging ───────────────────────────────────────────────────

    async def _log_violation(
        self,
        direction: str,
        content: str,
        result: dict,
        __user__: dict,
        __request__=None,
    ):
        """
        Log violation to the configured Knowledge Base.
        Uses the same pattern as v2: upload file → attach to KB → process/index.
        The KB must already exist in OpenWebUI.
        """
        timestamp = datetime.datetime.now().isoformat()

        # 1. Always log locally
        try:
            record = {
                "timestamp": timestamp,
                "direction": direction,
                "user_id": __user__.get("id", "unknown") if __user__ else "unknown",
                "user_safe": result["user_safe"],
                "response_safe": result["response_safe"],
                "categories": result["categories"],
                "content_preview": content[:400],
                "raw_verdict": result["raw"],
            }
            logger.info(f"[SafetyGuard] Violation: {json.dumps(record)}")
        except Exception as e:
            logger.warning(f"[SafetyGuard] Local violation logging error: {e}")

        # 2. Remote KB logging
        if not self.valves.violation_kb or self.valves.violation_kb.lower() == "none":
            return

        if not all([upload_file_handler, process_file, Knowledges, Users, run_in_threadpool]):
            logger.warning("[SafetyGuard] Required OpenWebUI modules not available for KB logging")
            return

        if not __request__ or not __user__:
            logger.warning("[SafetyGuard] Missing request or user context for KB logging")
            return

        try:
            # Resolve User object
            user_obj = await run_in_threadpool(Users.get_user_by_id, str(__user__["id"]))
            if not user_obj:
                logger.warning("[SafetyGuard] Could not resolve User object for KB logging")
                return

            # Find KB by name or ID — create if it doesn't exist
            kb_name = self.valves.violation_kb.strip()
            kb_id = None

            kbs = await run_in_threadpool(
                Knowledges.get_knowledge_bases_by_user_id, user_obj.id, "write"
            )
            if kbs:
                for kb in kbs:
                    if kb.id == kb_name or kb.name == kb_name:
                        kb_id = kb.id
                        break

            if not kb_id:
                # Auto-create the KB (same pattern as PubMed tool)
                try:
                    from open_webui.models.knowledge import KnowledgeForm

                    knowledge_form = KnowledgeForm(
                        name=kb_name,
                        description="Auto-created by Safety Guard Filter v3 for violation logging",
                        data={},
                    )
                    new_kb = await run_in_threadpool(
                        Knowledges.insert_new_knowledge,
                        user_obj.id,
                        knowledge_form,
                    )
                    if new_kb:
                        kb_id = new_kb.id
                        logger.info(f"[SafetyGuard] Created violation KB '{kb_name}' (ID: {kb_id})")
                    else:
                        logger.warning(f"[SafetyGuard] Failed to create violation KB '{kb_name}'")
                        return
                except Exception as create_err:
                    logger.warning(f"[SafetyGuard] Error creating violation KB '{kb_name}': {create_err}")
                    return

            # Prepare violation report content
            cats = ", ".join(result["categories"]) if result["categories"] else "unspecified"
            full_log_content = (
                f"--- Safety Violation Report ---\n"
                f"Timestamp: {timestamp}\n"
                f"Direction: {direction}\n"
                f"User ID: {__user__.get('id', 'unknown')}\n"
                f"User Name: {__user__.get('name', 'unknown')}\n"
                f"User Safety: {'safe' if result['user_safe'] else 'unsafe'}\n"
                f"Response Safety: {result['response_safe']}\n"
                f"Categories: {cats}\n"
                f"Raw Verdict: {result['raw']}\n"
                f"--- Content ---\n"
                f"{content[:500]}\n"
                f"-------------------------------\n"
            )

            filename = f"safety_violation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"

            # Upload file
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
                    __request__,
                    upload,
                    {"source": "safety_filter_v3", "type": "violation_report"},
                    False,  # process
                    False,  # process_in_background
                    user_obj,
                    None,
                )
            finally:
                await upload.close()

            # Get file ID (handle Pydantic model or dict)
            file_id = getattr(file_data, "id", None)
            if file_id is None and isinstance(file_data, dict):
                file_id = file_data.get("id")

            if not file_id:
                logger.warning("[SafetyGuard] Failed to upload violation report file")
                return

            # Attach file to KB
            try:
                await run_in_threadpool(
                    Knowledges.add_file_to_knowledge_by_id,
                    kb_id,
                    file_id,
                    user_obj.id,
                )
            except AttributeError:
                # Fallback for older OpenWebUI versions
                knowledge = Knowledges.get_knowledge_by_id(id=kb_id)
                if knowledge:
                    data = getattr(knowledge, "data", None) or {}
                    file_ids = data.get("file_ids", [])
                    if file_id not in file_ids:
                        file_ids.append(file_id)
                        data["file_ids"] = file_ids
                        Knowledges.update_knowledge_data_by_id(id=kb_id, data=data)

            # Process/index the file so it's searchable
            await run_in_threadpool(
                process_file,
                __request__,
                ProcessFileForm(file_id=file_id, collection_name=kb_id, content=full_log_content),
                user_obj,
            )

            logger.info(f"[SafetyGuard] Violation logged to KB '{kb_name}' (File ID: {file_id})")

        except Exception as e:
            logger.warning(f"[SafetyGuard] Error logging violation to KB: {e}")

    # ─── Inlet (user input check) ───────────────────────────────────────────

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        """Check user input for safety before passing to the main model."""
        if not self.valves.check_input:
            return body

        messages = body.get("messages", [])
        if not messages:
            return body

        # Get the latest user message
        user_msg = messages[-1].get("content", "")
        if not user_msg or not user_msg.strip():
            return body

        if __event_emitter__:
            await __event_emitter__(
                {"type": "status", "data": {"description": "Checking content safety...", "done": False}}
            )

        if self.valves.enable_step_debug:
            logger.info(f"[SafetyGuard] Inlet: checking user message ({len(user_msg)} chars)")

        result = await self._check_safety(
            user_message=user_msg,
            agent_response=None,
            __user__=__user__,
            __request__=__request__,
        )

        if __event_emitter__:
            safe_str = "\u2713 Safe" if result["user_safe"] else "\u26a0 Unsafe"
            await __event_emitter__(
                {"type": "status", "data": {"description": f"Safety check complete: {safe_str}", "done": True}}
            )

        if not result["user_safe"]:
            cats = ", ".join(result["categories"]) if result["categories"] else "unspecified"
            logger.warning(f"[SafetyGuard] BLOCKED inlet \u2014 categories: {cats}")

            await self._log_violation("inlet", user_msg, result, __user__, __request__)

            if self.valves.block_on_unsafe:
                raise ValueError(f"Content blocked by safety filter: {cats}")

        return body

    # ─── Outlet (assistant response check) ───────────────────────────────────

    async def outlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        """Check assistant response for safety before showing to user."""
        if not self.valves.check_output:
            return body

        messages = body.get("messages", [])
        if not messages:
            return body

        # Find the last user message and last assistant message
        user_msg = ""
        assistant_msg = ""
        for msg in reversed(messages):
            if msg.get("role") == "assistant" and not assistant_msg:
                assistant_msg = msg.get("content", "")
            elif msg.get("role") == "user" and not user_msg:
                user_msg = msg.get("content", "")
            if user_msg and assistant_msg:
                break

        if not assistant_msg or not assistant_msg.strip():
            return body

        if __event_emitter__:
            await __event_emitter__(
                {"type": "status", "data": {"description": "Checking response safety...", "done": False}}
            )

        if self.valves.enable_step_debug:
            logger.info(f"[SafetyGuard] Outlet: checking response ({len(assistant_msg)} chars)")

        result = await self._check_safety(
            user_message=user_msg,
            agent_response=assistant_msg,
            __user__=__user__,
            __request__=__request__,
        )

        if __event_emitter__:
            safe_str = "\u2713 Safe" if result.get("response_safe", True) else "\u26a0 Unsafe"
            await __event_emitter__(
                {"type": "status", "data": {"description": f"Safety check complete: {safe_str}", "done": True}}
            )

        # For outlet, check response safety specifically
        is_unsafe = False
        if result["response_safe"] is not None and not result["response_safe"]:
            is_unsafe = True
        elif not result["user_safe"]:
            # If user was unsafe, the response might still be safe (refusal)
            # Only block if response is also flagged
            is_unsafe = result["response_safe"] is not None and not result["response_safe"]

        if is_unsafe:
            cats = ", ".join(result["categories"]) if result["categories"] else "unspecified"
            logger.warning(f"[SafetyGuard] BLOCKED outlet — categories: {cats}")

            await self._log_violation("outlet", assistant_msg, result, __user__, __request__)

            if self.valves.block_on_unsafe:
                # Replace the assistant's message with the safe message
                for msg in reversed(messages):
                    if msg.get("role") == "assistant":
                        msg["content"] = (
                            f"{self.valves.unsafe_message}\n\n"
                            f"[Safety categories: {cats}]"
                        )
                        break

        return body
