"""
Prompt Injection Protection Filter for Open WebUI
Filters user inputs for prompt injection attempts using a dedicated detection model.
version 2.0.0
requirements: pydantic
"""

from typing import Optional, Callable, Awaitable, List, Any
from pydantic import BaseModel, Field
import datetime
from tempfile import SpooledTemporaryFile
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

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
    Open WebUI Filter implementation for prompt injection protection.
    """

    class Valves(BaseModel):
        priority: int = -100
        enabled: bool = True
        injection_detection_model_id: str = Field(
            default="",
            description="Model ID for semantic prompt injection detection. The model's system prompt defines detection logic. Should return 'SAFE' or 'INJECTION' classification. Example: 'prompt-injection-detector'",
        )
        block_on_unsafe: bool = True
        enable_full_debug: bool = Field(
            default=False,
            description="Enable heavy debugging logs, including payloads/results (masked & truncated).",
        )
        enable_step_debug: bool = Field(
            default=False,
            description="Enable step-by-step progress logs (concise, truncated).",
        )
        violation_kb: str = Field(
            default="Prompt Injection Violations",
            description="Knowledge base name for logging violations.",
        )
        max_violations_count: int = Field(
            default=3,
            description="Maximum number of violations before user lockout.",
        )
        admin_email: str = Field(
            default="",
            description="Admin email address to notify on lockout.",
        )
        smtp_host: str = Field(
            default="smtp.gmail.com",
            description="SMTP server hostname.",
        )
        smtp_port: int = Field(
            default=587,
            description="SMTP server port.",
        )
        smtp_user: str = Field(
            default="",
            description="SMTP username.",
        )
        smtp_password: str = Field(
            default="",
            description="SMTP password.",
        )
        smtp_use_tls: bool = Field(
            default=True,
            description="Use TLS encryption.",
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

    async def _disable_user(self, user_id: str) -> bool:
        """
        Disable a user account by updating their role to 'pending'.
        """
        self._dbg_step(f"Attempting to disable user {user_id}")
        try:
            # Try to update user role to 'pending'
            # Assuming Users.update_user_role_by_id exists
            if hasattr(Users, "update_user_role_by_id"):
                await run_in_threadpool(Users.update_user_role_by_id, user_id, "pending")
                self._dbg_step(f"User {user_id} disabled via update_user_role_by_id")
                return True
            # Fallback: try update_user_by_id
            elif hasattr(Users, "update_user_by_id"):
                 await run_in_threadpool(Users.update_user_by_id, user_id, {"role": "pending"})
                 self._dbg_step(f"User {user_id} disabled via update_user_by_id")
                 return True
            else:
                self._dbg_step("Could not find method to disable user (Users.update_user_role_by_id or Users.update_user_by_id)")
                return False
        except Exception as e:
            self._dbg_step(f"Error disabling user: {e}")
            return False

    async def _send_email(self, user_id: str, content: str, reason: str) -> None:
        """
        Send an email notification to the admin.
        """
        if not self.valves.admin_email:
            self._dbg_step("No admin email configured, skipping email notification")
            return

        self._dbg_step(f"Sending email notification to {self.valves.admin_email}")
        
        subject = f"User Lockout Notification: {user_id}"
        body = f"""
User {user_id} has been locked out due to excessive prompt injection violations.

Reason: {reason}
Timestamp: {datetime.datetime.now().isoformat()}

Last Content:
{self._truncate(content, 1000)}
"""

        msg = MIMEMultipart()
        msg["From"] = formataddr((self.valves.smtp_user or "Open WebUI", self.valves.smtp_user))
        msg["To"] = self.valves.admin_email
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        try:
            def send():
                with smtplib.SMTP(self.valves.smtp_host, self.valves.smtp_port) as server:
                    if self.valves.smtp_use_tls:
                        server.starttls()
                    if self.valves.smtp_user and self.valves.smtp_password:
                        server.login(self.valves.smtp_user, self.valves.smtp_password)
                    server.send_message(msg)
            
            await run_in_threadpool(send)
            self._dbg_step("Email notification sent successfully")
        except Exception as e:
            self._dbg_step(f"Error sending email: {e}")

    async def _increment_violation_count(self, user_id: str) -> int:
        """
        Increments the persistent violation count for a user.
        Returns the new count.
        """
        if not Users:
            self._dbg_step("Users module not available, cannot persist violation count")
            return 0

        try:
            # 1. Get the current user object
            user = await run_in_threadpool(Users.get_user_by_id, user_id)
            if not user:
                self._dbg_step(f"User {user_id} not found")
                return 0

            # 2. Access the existing 'info' dictionary
            # Handle cases where info might be None or missing
            current_info = getattr(user, "info", {}) or {}
            if not isinstance(current_info, dict):
                current_info = {}
            
            # 3. Increment the count
            current_count = current_info.get("violation_count", 0)
            new_count = current_count + 1
            current_info["violation_count"] = new_count
            
            # 4. Persist the changes
            await run_in_threadpool(Users.update_user_by_id, user_id, {"info": current_info})
            self._dbg_step(f"Persisted violation count for {user_id}: {new_count}")
            
            return new_count
            
        except Exception as e:
            self._dbg_step(f"Error updating violation count for {user_id}: {e}")
            return 0

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        """
        Filter incoming user messages for prompt injection attempts.
        """
        self._dbg_full("Inlet called with body:", body)
        if not self.valves.enabled:
            self._dbg_step("Inlet skipped: Disabled")
            return body

        # Store request and user for internal API calls
        self.__request__ = __request__
        self.__user__ = __user__

        messages = body.get("messages", [])
        if not messages:
            self._dbg_step("Inlet skipped: No messages")
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
                model_name = body.get("model", "unknown")
                await self.log_violation(__user__, user_content, injection_reason, __request__, model_name=model_name)
                
                # Lockout Logic - Skip for admin users
                user_id = __user__.get("id") if __user__ else "unknown"
                user_role = __user__.get("role") if __user__ else "user"
                
                if user_id != "unknown" and user_role != "admin":
                    # Use persistent counter
                    violation_count = await self._increment_violation_count(user_id)
                    self._dbg_step(f"User {user_id} violation count: {violation_count}/{self.valves.max_violations_count}")
                    
                    if violation_count >= self.valves.max_violations_count:
                        self._dbg_step(f"User {user_id} reached max violations. Locking out.")
                        if await self._disable_user(user_id):
                            await self._send_email(user_id, user_content, injection_reason)
                        else:
                            self._dbg_step(f"Failed to disable user {user_id}")
                elif user_role == "admin":
                    self._dbg_step(f"Skipping lockout for admin user {user_id}")

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
                self._dbg_step("Emitting status: Prompt injection check complete")
                await __event_emitter__(
                    {
                        "type": "status",
                        "data": {
                            "description": "Prompt injection check complete: ✓ Safe",
                            "done": True,
                        },
                    }
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
                f"--- Prompt Injection Violation Report ---\n"
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

            filename = f"injection_violation_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            
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
                    {"source": "prompt_injection_filter", "type": "violation_report"}, # metadata
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

    async def _detect_prompt_injection_semantic(self, content: str) -> tuple[bool, str]:
        """
        PHASE 1: Semantic prompt injection detection using dedicated model.
        NO HARD-CODED PROMPTS. Model's system prompt defines detection logic.
        
        Returns:
            tuple: (is_safe: bool, reason: str)
        """
        self._dbg_step(f"Starting semantic injection detection for content: '{content}'")
        self._dbg_step(f"Using injection detection model ID: '{self.valves.injection_detection_model_id}'")
        
        # Check if model ID is configured
        if not self.valves.injection_detection_model_id:
            self._dbg_step("No injection detection model ID configured; skipping detection as safe")
            return True, ""
        
        try:
            # Import internal Open WebUI function for generating chat completions
            from open_webui.utils.chat import generate_chat_completion
            
            # Build payload for internal API
            payload = {
                "model": self.valves.injection_detection_model_id,
                "messages": [{"role": "user", "content": content}],
                "stream": False,
            }
            
            self._dbg_full(f"Querying injection detection model with payload: {str(payload)}")
            
            # Use internal generate_chat_completion with __request__ from extra_params
            # Note: This requires __request__ and __user__ to be available in the filter context
            response = await generate_chat_completion(
                request=self.__request__,
                form_data=payload,
                user=self.__user__,
                bypass_filter=True,  # Important: bypass to avoid infinite recursion
            )
            
            self._dbg_step(f"Injection detection response received")
            
            # Handle response
            if isinstance(response, dict):
                # Non-streaming response
                choices = response.get("choices", [])
                if not choices or not isinstance(choices, list) or not choices:
                    self._dbg_step("No 'choices' array in model response")
                    return True, ""
                
                message = choices[0].get("message", {})
                response_text = message.get("content", "")
            else:
                self._dbg_step(f"Unexpected response type: {type(response)}")
                return True, ""
            
            self._dbg_step(f"Injection detection response: {response_text}")
            
            # Granular parsing: handle 'SAFE' and 'INJECTION: reason' (case-insensitive)
            response_str = str(response_text).strip()
            response_lower = response_str.lower()

            # SAFE exactly (allow trailing/leading spaces)
            if response_lower == "safe":
                return True, ""

            # INJECTION with optional reason after ':'
            if response_lower.startswith("injection"):
                reason = "Prompt Injection Detected"
                # Extract reason after first ':' if present
                if ":" in response_str:
                    reason_part = response_str.split(":", 1)[1].strip()
                    if reason_part:
                        reason = reason_part
                return False, reason
            
            # Any other output: fail-open
            return True, ""
            
        except Exception as e:
            self._dbg_step(f"Injection detection exception: {e}")
            # Fail-open: do not block on unexpected exceptions
            return True, ""

