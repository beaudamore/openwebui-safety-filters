# OpenWebUI Internal Library Usage Patterns

This document shows how to access OpenWebUI's internal libraries in custom filters/pipelines, based on the `safety_filter_guard_v1.py` pattern.

> **Scope:** These are auxiliary Open WebUI extension patterns, not APIs used by the active `pipeline-public` blueprint. Internal Open WebUI imports are version-dependent and must be verified against the deployed Open WebUI source.

---

## 🔑 Core Pattern: Guarded Imports

**Always use try/except blocks** to handle environments outside OpenWebUI runtime:

```python
# Standard pattern for all OpenWebUI filter/pipeline imports
try:
    from open_webui.utils.chat import generate_chat_completion
    from open_webui.models.knowledge import Knowledges
    from open_webui.models.users import Users
    from open_webui.routers.files import upload_file_handler
    from open_webui.routers.retrieval import process_file, ProcessFileForm
    from fastapi import UploadFile
    from fastapi.concurrency import run_in_threadpool
except ImportError:
    # Set to None for graceful degradation
    generate_chat_completion = None
    Knowledges = None
    Users = None
    upload_file_handler = None
    process_file = None
    ProcessFileForm = None
    UploadFile = None
    run_in_threadpool = None
```

**Why?**
- Filters are loaded at startup before OpenWebUI modules are available
- Syntax validation happens in isolation
- Import errors don't crash the entire system

---

## 📚 Common Library Imports

### 1. Chat Completions (LLM Queries)
```python
from open_webui.utils.chat import generate_chat_completion

# Usage in filter:
response = await generate_chat_completion(
    request=__request__,
    form_data={
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "Hello"}],
        "stream": False,
    },
    user=__user__,
    bypass_filter=True,  # Skip filter chain for internal calls
)
```

### 2. Configuration Access
```python
# No import needed - use __request__ context
config = __request__.app.state.config

# Example: Get TTS settings
tts_engine = getattr(config, "TTS_ENGINE", "openai")
tts_model = getattr(config, "TTS_MODEL", "tts-1")
tts_api_key = getattr(config, "TTS_OPENAI_API_KEY", "")
tts_base_url = getattr(config, "TTS_OPENAI_API_BASE_URL", "https://api.openai.com/v1")
```

### 3. Environment Variables
```python
from open_webui.env import (
    AIOHTTP_CLIENT_TIMEOUT,
    AIOHTTP_CLIENT_SESSION_SSL,
    ENABLE_FORWARD_USER_INFO_HEADERS,
    DEVICE_TYPE,
)

# Usage:
timeout = aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT)
async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
    async with session.post(url, json=data, ssl=AIOHTTP_CLIENT_SESSION_SSL) as r:
        # ...
```

### 4. User Management
```python
from open_webui.models.users import Users
from fastapi.concurrency import run_in_threadpool

# Usage:
user_obj = await run_in_threadpool(Users.get_user_by_id, str(__user__["id"]))
```

### 5. Knowledge Base Operations
```python
from open_webui.models.knowledge import Knowledges
from open_webui.routers.files import upload_file_handler
from open_webui.routers.retrieval import process_file, ProcessFileForm
from fastapi import UploadFile
from fastapi.concurrency import run_in_threadpool

# Example: Upload file to KB
upload = UploadFile(filename="data.txt", file=SpooledTemporaryFile())
file_data = await run_in_threadpool(
    upload_file_handler,
    __request__,
    upload,
    {"source": "filter"},  # metadata
    False,  # process
    False,  # process_in_background
    user_obj,
    None,
)

# Attach to knowledge base
await run_in_threadpool(
    Knowledges.add_file_to_knowledge_by_id,
    kb_id,
    file_data.id,
    user_obj.id,
)
```

### 6. HTTP Headers (User Info Forwarding)
```python
from open_webui.utils.headers import include_user_info_headers

# Usage:
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}",
}

if ENABLE_FORWARD_USER_INFO_HEADERS and __user__:
    headers = include_user_info_headers(headers, __user__)
```

---

## 🎯 Filter Hook Context Variables

All filter hooks receive these parameters:

```python
async def inlet(
    self,
    body: dict,                      # Request body (messages, model, etc.)
    __user__: Optional[dict] = None, # User context: {"id", "email", "name", "role"}
    __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,  # Status updates
    __request__: Optional[Any] = None,  # FastAPI Request object (access to app.state)
) -> dict:
    # ...
```

### `__user__` Structure
```python
{
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "email": "user@example.com",
    "name": "John Doe",
    "role": "user"  # or "admin"
}
```

### `__request__` Structure
```python
__request__.app.state.config  # Global configuration
__request__.app.state.speech_synthesiser  # TTS pipeline
__request__.app.state.faster_whisper_model  # STT model
__request__.app.state.OPENAI_API_BASE_URLS  # Model endpoints
__request__.app.state.OPENAI_API_KEYS  # API keys
```

### `__event_emitter__` Usage
```python
# Send status updates to UI
if __event_emitter__:
    await __event_emitter__({
        "type": "status",
        "data": {
            "description": "Processing request...",
            "done": False,
        },
    })

# Mark as complete
if __event_emitter__:
    await __event_emitter__({
        "type": "status",
        "data": {
            "description": "Complete!",
            "done": True,
        },
    })
```

---

## 🔧 Async/Sync Bridge Pattern

OpenWebUI uses FastAPI (async) but some operations are synchronous. Use `run_in_threadpool`:

```python
from fastapi.concurrency import run_in_threadpool

# Sync function call in async context
result = await run_in_threadpool(
    sync_function,
    arg1,
    arg2,
    kwarg1=value1,
)

# Example: Database operations
user_obj = await run_in_threadpool(Users.get_user_by_id, user_id)
kb_list = await run_in_threadpool(Knowledges.get_knowledge_bases_by_user_id, user_id, "write")
```

---

## 📦 File I/O Patterns

### Async File Operations
```python
import aiofiles

# Write file
async with aiofiles.open(file_path, "wb") as f:
    await f.write(data_bytes)

# Read file
async with aiofiles.open(file_path, "r") as f:
    content = await f.read()
```

### HTTP Downloads (Streaming)
```python
import aiohttp
from open_webui.env import AIOHTTP_CLIENT_TIMEOUT, AIOHTTP_CLIENT_SESSION_SSL

timeout = aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT)
async with aiohttp.ClientSession(timeout=timeout, trust_env=True) as session:
    async with session.post(url, json=payload, ssl=AIOHTTP_CLIENT_SESSION_SSL) as r:
        r.raise_for_status()
        
        # Stream to file
        async with aiofiles.open(output_path, "wb") as f:
            await f.write(await r.read())
```

---

## 🧪 Example: Complete Filter with Internal Libraries

```python
"""
Example filter using OpenWebUI internal libraries
"""
from typing import Optional, Callable, Awaitable, Any
from pydantic import BaseModel, Field

# Guarded imports
try:
    from open_webui.utils.chat import generate_chat_completion
    from open_webui.env import AIOHTTP_CLIENT_TIMEOUT, ENABLE_FORWARD_USER_INFO_HEADERS
    from open_webui.utils.headers import include_user_info_headers
    from fastapi.concurrency import run_in_threadpool
    import aiohttp
    import aiofiles
    LIBS_AVAILABLE = True
except ImportError:
    LIBS_AVAILABLE = False


class Filter:
    class Valves(BaseModel):
        enabled: bool = Field(default=True)
        api_key: str = Field(default="")

    def __init__(self):
        self.valves = self.Valves()

    async def inlet(
        self,
        body: dict,
        __user__: Optional[dict] = None,
        __event_emitter__: Optional[Callable[[dict], Awaitable[None]]] = None,
        __request__: Optional[Any] = None,
    ) -> dict:
        if not LIBS_AVAILABLE or not self.valves.enabled:
            return body

        # Access config
        config = __request__.app.state.config
        tts_engine = getattr(config, "TTS_ENGINE", "openai")

        # Send status
        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "Processing...", "done": False},
            })

        # Query internal model
        response = await generate_chat_completion(
            request=__request__,
            form_data={
                "model": "gpt-4o",
                "messages": body["messages"],
                "stream": False,
            },
            user=__user__,
            bypass_filter=True,
        )

        # HTTP request with proper headers
        headers = {"Authorization": f"Bearer {self.valves.api_key}"}
        if ENABLE_FORWARD_USER_INFO_HEADERS and __user__:
            headers = include_user_info_headers(headers, __user__)

        timeout = aiohttp.ClientTimeout(total=AIOHTTP_CLIENT_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get("https://api.example.com/data", headers=headers) as r:
                data = await r.json()

        # Complete
        if __event_emitter__:
            await __event_emitter__({
                "type": "status",
                "data": {"description": "Done!", "done": True},
            })

        return body
```

---

## 🚨 Error Handling Best Practices

### 1. Graceful Degradation
```python
if not LIBS_AVAILABLE:
    print("Required libraries not available - filter disabled")
    return body  # Pass through without processing
```

### 2. Missing Context
```python
if not __request__:
    print("No request context - cannot access config")
    return body

if not __user__:
    print("No user context - skipping user-specific logic")
    # Continue with limited functionality
```

### 3. HTTP Errors
```python
try:
    async with session.post(url, json=data) as r:
        r.raise_for_status()
        result = await r.json()
except aiohttp.ClientError as e:
    print(f"HTTP error: {e}")
    return body  # Fail gracefully
except Exception as e:
    print(f"Unexpected error: {e}")
    return body
```

---

## 📊 Performance Tips

### 1. Cache Expensive Operations
```python
class Filter:
    def __init__(self):
        self._model_cache = {}  # Cache model metadata
        self._config_cache = {}  # Cache config values

    async def inlet(self, body, __request__, ...):
        # Check cache first
        if "tts_engine" not in self._config_cache:
            config = __request__.app.state.config
            self._config_cache["tts_engine"] = getattr(config, "TTS_ENGINE", "openai")
        
        tts_engine = self._config_cache["tts_engine"]
```

### 2. Batch Operations
```python
# Bad: Sequential queries
for speaker in speakers:
    audio = await generate_audio(speaker)  # Slow!

# Good: Parallel queries
import asyncio
audio_tasks = [generate_audio(s) for s in speakers]
audio_results = await asyncio.gather(*audio_tasks)  # Fast!
```

### 3. Stream Large Files
```python
# Bad: Load entire file into memory
data = await r.read()
await f.write(data)

# Good: Stream chunks
async for chunk in r.content.iter_chunked(8192):
    await f.write(chunk)
```

---

## 🔍 Debugging

### Enable Internal Logging
```python
import logging
log = logging.getLogger(__name__)

log.debug(f"Config TTS engine: {tts_engine}")
log.info(f"Processing {len(speakers)} speakers")
log.error(f"Failed to generate audio: {e}")
```

### Print to Console (Development Only)
```python
def _dbg(self, *args):
    if self.valves.enable_debug:
        try:
            print("[MyFilter]", *args)
        except Exception:
            pass  # Avoid crashes from print errors
```

---

## 📚 Reference Files

| Purpose | File Path |
|---------|-----------|
| TTS implementation | `backend/open_webui/routers/audio.py` |
| Chat completions | `backend/open_webui/utils/chat.py` |
| Config management | `backend/open_webui/config.py` |
| Environment vars | `backend/open_webui/env.py` |
| User models | `backend/open_webui/models/users.py` |
| Knowledge base | `backend/open_webui/models/knowledge.py` |
| Example filter | `filters/safety/safety_filter_guard_v1.py` |

---

## ✅ Checklist for New Filters

- [ ] Guarded imports with try/except
- [ ] Check `LIBS_AVAILABLE` before using internal functions
- [ ] Validate `__request__` exists before accessing config
- [ ] Use `run_in_threadpool` for sync operations
- [ ] Use `aiohttp.ClientTimeout` for HTTP requests
- [ ] Use `AIOHTTP_CLIENT_SESSION_SSL` for SSL context
- [ ] Forward user headers with `include_user_info_headers`
- [ ] Emit status updates via `__event_emitter__`
- [ ] Handle errors gracefully (return `body` on failure)
- [ ] Add debug logging for troubleshooting
- [ ] Test without OpenWebUI runtime (syntax validation)
- [ ] Test with missing context (`__user__`, `__request__`)

---

## 💡 Key Takeaways

1. **Always guard imports** - Filters load before OpenWebUI modules
2. **Access config via request** - `__request__.app.state.config`
3. **Bridge sync/async** - Use `run_in_threadpool` for sync calls
4. **Fail gracefully** - Return `body` unchanged on errors
5. **Follow safety filter pattern** - It's the reference implementation
6. **Use internal utilities** - Don't reimplement what OpenWebUI provides
7. **Respect user context** - Forward headers, check permissions
8. **Emit status updates** - Keep users informed of long operations
9. **Cache when possible** - Reduce redundant config/API lookups
10. **Test in isolation** - Ensure filter works without full OpenWebUI stack
