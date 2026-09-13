# Open WebUI Safety Filters

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python&logoColor=white)
![OpenWebUI](https://img.shields.io/badge/Open_WebUI-Filter-green?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC40OCAxMC0xMFMxNy41MiAyIDEyIDJ6Ii8+PC9zdmc+)
![ClamAV](https://img.shields.io/badge/ClamAV-Antivirus-red?logo=data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIyNCIgaGVpZ2h0PSIyNCIgdmlld0JveD0iMCAwIDI0IDI0IiBmaWxsPSJ3aGl0ZSI+PHBhdGggZD0iTTEyIDJDNi40OCAyIDIgNi40OCAyIDEyczQuNDggMTAgMTAgMTAgMTAtNC40OCAxMC0xMFMxNy41MiAyIDEyIDJ6Ii8+PC9zdmc+)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Enterprise](https://img.shields.io/badge/Enterprise-Ready-purple)

A comprehensive collection of content filtering and safety modules for Open WebUI. These filters provide protection against malware, harmful content, policy violations, and prompt injection attacks.

## Author

**Beau D'Amore**  
[www.damore.ai](https://www.damore.ai)

## Overview

This repository contains multiple safety filter implementations designed to protect Open WebUI deployments by scanning user inputs for various threats and policy violations. All filters are input-only: a blocked prompt never reaches the model, and the user sees one aggregated block reply instead of an error. All filters follow the Open WebUI Filter interface specification.

Shared Open WebUI extension patterns used by these filters are documented in [docs/openwebui-internal-library-patterns.md](docs/openwebui-internal-library-patterns.md).

### Available Filters

1. **Antivirus/Antimalware Filter** (`antivirus/filter/safety_filter_antivirus_antimalware.py`)
   - Scans file uploads with ClamAV for viruses and malware
   - Integrates with ClamAV daemon for real-time threat detection
   - Automatically blocks infected files and logs violations

2. **Content Safety Filter** (`content_safety/filter/safety_guard_filter_v3_latest.py`)
   - Filters user inputs for harmful content
    - Uses an internal Open WebUI safety model for content classification
    - Detects a configurable 23-category safety taxonomy
   - Advanced safety filtering with policy augmentation
   - Integrates with Open WebUI's internal chat completion system
   - Supports optional policy augmentation via direct API calls
   - Includes comprehensive logging and debugging capabilities

3. **Policy Violation Filter** (`policy_violation/filter/safety_filter_company_policy_violation_v1.py`)
   - Detects potential company policy violations in user input
   - Uses Open WebUI's internal chat system and vector database
   - Customizable policy rules and violation detection thresholds
   - Tracks violation history per user

4. **Prompt Injection Filter** (`prompt_injection/filter/safety_filter_prompt_injection_v2.py`)
   - Detects and prevents prompt injection attacks
   - Uses semantic analysis for advanced attack detection
   - Configurable detection models and sensitivity levels

## Installation

## Open WebUI Compatibility

These filters are verified against **Open WebUI 0.11.3** (image `ghcr.io/open-webui/open-webui:main`, commit `0a7c158`, 2026-09-12). Each filter file carries an `openwebui:` line in its header stating the version it was last verified against.

| Filter | File | Filter version | Verified against |
|---|---|---|---|
| Antivirus/Antimalware | `antivirus/filter/safety_filter_antivirus_antimalware.py` | 1.1.0 | Open WebUI 0.11.3 |
| Content Safety (Safety Guard v3) | `content_safety/filter/safety_guard_filter_v3_latest.py` | 3.1.0 | Open WebUI 0.11.3 |
| Policy Violation | `policy_violation/filter/safety_filter_company_policy_violation_v1.py` | 1.1.0 | Open WebUI 0.11.3 |
| Prompt Injection | `prompt_injection/filter/safety_filter_prompt_injection_v2.py` | 2.1.0 | Open WebUI 0.11.3 |

Open WebUI changes its internal helpers often, and filters fail open silently when a helper disappears. The filters depend on these internals as of 0.11.3; if an update changes any of them, expect the status line under a message to read `FAILED (not enforced)` rather than a pass:

- `Users`, `Files`, `Knowledges` and `Functions` model methods are all `async` and are awaited directly.
- `Knowledges.get_knowledge_bases_by_user_id` no longer exists. Filters list all knowledge bases with `Knowledges.get_knowledge_bases()` and match by id or name, creating the base with `insert_new_knowledge` when missing.
- A direct call to `routers.retrieval.process_file` needs an explicit session: `async with AsyncSessionLocal() as db: await process_file(..., db=db)`. Calling it without one fails with `'Depends' object has no attribute 'commit'`.
- `routers.files.upload_file_handler` links and indexes a file itself when the metadata carries `knowledge_id` and `process=True`.
- The fall-through block pattern resolves the filter chain with `utils.filter.resolve_filter_pipeline` and inspects later filters through `utils.plugin.get_function_module_from_cache`, which returns the `Filter` **instance**, not the module.
- A filter ends a turn without calling the model by emitting a `replace` event with the reply text and raising `asyncio.CancelledError`; Open WebUI treats that as a cancelled turn, not an error, so the chat stays usable. An error with no content would trigger the "error in the previous response" toast and block further input.

**After every Open WebUI update**, send one prompt that trips more than one filter (for example a harassment request combined with an override attempt and an EICAR attachment). Expect one block reply listing every filter that fired. That single check exercises the chain resolver, the cache marker, the `replace` event and the cancel path.

### Prerequisites

- Python 3.8+
- Open WebUI instance
- ClamAV daemon (for antivirus filter only)
- Docker and Docker Compose (optional, for containerized ClamAV)

### Setup

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd filters
   ```

2. **Install dependencies (if running standalone):**
   ```bash
   pip install -r requirements.txt
   ```

3. **Copy filters to Open WebUI:**
   - Copy filter files to your Open WebUI `filters` directory
   - Typically located at: `/path/to/open-webui/app/filters/`

4. **Configure ClamAV (for antivirus filter):**
   ```bash
   docker-compose -f docker-compose.clamav.yml up -d
   ```

## Configuration

### Common Settings (All Filters)

Each filter uses a `Valves` configuration class with the following common settings:

```python
class Valves(BaseModel):
    priority: int = 0              # Execution priority (-200 to 100)
    enabled: bool = True           # Enable/disable filter
    block_mode: str = "message"    # "message": static reply, no model call (default); "error": raise (old behaviour)
    block_message: str = "⛔ This message was blocked by a safety filter and was not sent to the model. You can continue the conversation."
```

`block_mode="message"` is the tested default. Keep `block_message` identical across filters; whichever filter runs last shows it, followed by one bullet per filter that fired. The Content Safety filter has no `enabled` valve.

### Antivirus/Antimalware Filter

**Configuration Options:**

```python
scan_attached_files: bool = True
    # Enable scanning of files attached to messages

clamav_url: str = "http://localhost:3310"
    # ClamAV daemon endpoint URL. Inside the Open WebUI container "localhost" is not ClamAV:
    # use http://host.docker.internal:3310 (published port) or http://clamav:3310 when both
    # containers share a Docker network. Files are streamed to ClamAV (INSTREAM), so ClamAV
    # never needs access to Open WebUI's uploads directory.

clamav_timeout: float = 30.0
    # Scan timeout in seconds

block_on_detection: bool = True
    # Block file if malware is detected

delete_infected_files: bool = False
    # Delete infected files from storage

violation_kb: str = "Malware Violations"
    # Knowledge base for logging detections

max_violations_count: int = 3
    # Max violations before user status change

enable_full_debug: bool = False
    # Enable detailed debugging logs

enable_step_debug: bool = False
    # Enable step-by-step progress logs
```

**Usage Example:**
1. Navigate to Open WebUI admin panel
2. Go to Settings → Filters
3. Enable "Antivirus/Antimalware Filter"
4. Configure ClamAV URL and timeout
5. Adjust violation thresholds as needed

### Content Safety Filter

**Configuration Options:**

```python
safety_model_id: str = "safety-guard-qwen3-14b"
    # Open WebUI model ID for the safety classifier. The filter builds the full
    # Nemotron-style classification prompt itself, so this can be a workspace model on
    # your base model with the minimal JSON-only system prompt in
    # content_safety/prompt/safety_filter_guard_v3.md (or the trained LoRA when served).

block_on_unsafe: bool = True
    # Block unsafe content

violation_kb: str = ""
    # Knowledge base for logging violations (empty disables logging)

harm_categories: List[str]
    # Use S1_* through S23_* valves to enable/disable categories
```

### Policy Violation Filter

**Configuration Options:**

```python
policy_model_id: str = "prompt-safety-and-policy-violation-detector"
    # Model ID for policy violation detection

block_on_unsafe: bool = True
    # Block policy violations

compliance_kb: str = "Company Policies"
    # Comma-separated knowledge base name(s) whose documents are added to the check prompt

violation_kb: str = "Company Policy Violations"
    # Knowledge base for logging violations (created if missing)

enable_full_debug: bool = False
    # Detailed debugging logs
```

### Prompt Injection Filter

**Configuration Options:**

```python
injection_detection_model_id: str = ""
    # Model ID for semantic injection detection

block_on_unsafe: bool = True
    # Block detected injections

violation_kb: str = "Prompt Injection Violations"
    # Knowledge base for logging violations (created if missing)

enable_full_debug: bool = False
    # Detailed debugging logs

enable_step_debug: bool = False
    # Step-by-step progress logs

enable_webhook_notifications: bool = False
    # Send webhook notification when a user is locked out

notification_webhook_url_env: str = "PROMPT_INJECTION_WEBHOOK_URL"
    # Env var containing the webhook URL

notification_webhook_subject: str = "Prompt injection lockout"
    # Subject/title included in webhook payloads
```

The webhook sends a generic JSON `POST` with `event`, `subject`, `user_id`, `user_name`, `user_email`, `reason`, `timestamp`, and `content_preview`. Put webhook secrets in the Open WebUI container environment, not in filter valves. Provider-specific formatting and fan-out to Slack, Google Workspace, email, tickets, or other alerting systems should live in the webhook receiver.

For Compose or Portainer, add this environment variable to the Open WebUI container:

```yaml
environment:
    PROMPT_INJECTION_WEBHOOK_URL: ${PROMPT_INJECTION_WEBHOOK_URL}
```

In Portainer, create the stack variable `PROMPT_INJECTION_WEBHOOK_URL` with the generic webhook receiver URL as its value. The stack YAML should reference the variable; it should not contain the URL directly.

If Open WebUI and the webhook receiver are on the same Docker host and same Docker network, use:

```text
http://webhook-alerts:8080/webhooks/openwebui/prompt-injection-lockout
```

If Open WebUI is on another Docker host or network, use a URL reachable from the Open WebUI container:

```text
http://<docker-host-ip-or-dns>:8080/webhooks/openwebui/prompt-injection-lockout
```

If the receiver is exposed through HTTPS, use the public HTTPS URL:

```text
https://<public-hostname>/webhooks/openwebui/prompt-injection-lockout
```

Do not use `PROMPT_INJECTION_SLACK_WEBHOOK_URL` unless you intentionally change `notification_webhook_url_env` to that exact env var name.

Then set the filter valves to reference the env var name:

```yaml
enable_webhook_notifications: true
notification_webhook_url_env: "PROMPT_INJECTION_WEBHOOK_URL"
```

## Architecture

### Filter Interface

All filters implement the Open WebUI Filter interface:

```python
class Filter:
    class Valves(BaseModel):
        # Configuration settings
        pass
    
    async def inlet(self, body: dict, **kwargs) -> dict:
        """Process incoming user messages"""
        pass
```

All filters are input-only. Output (outlet) checks were removed on purpose: the outlet runs after the response has already streamed to the user, so replacing it afterwards is a leak with a cosmetic patch. Output screening, if added, belongs in a separate `stream`-hook filter with its own rules.

### Execution Flow

1. **Inlet Phase**: User message enters → each filter checks the original input in priority order
2. **Violation Logging**: Every filter that detects something logs to its own knowledge base and applies its lockout counter
3. **Block**: The last block-aware filter in the chain shows the aggregated block reply and ends the turn; the model is never called
4. **User Status**: User may be flagged for review based on violation count

### Block Pattern (shared by all filters)

Every filter carries `FILTER_BLOCK_AWARE = True` on its `Filter` class and the same small set of helpers:

- On a detection the filter does its own logging and lockout, then `_record_block(body, reason)` appends the reason to `body["metadata"]["filter_block"]` (request metadata is never sent to the model) and returns the prompt **untouched**, so later filters still scan the same text.
- After every inlet run, `_enforce_block_if_last` asks Open WebUI's chain resolver whether any later block-aware filter will run. If so it defers; if not, and something was recorded, `_block_turn` emits the static `block_message` plus one bullet per reason and cancels the turn. If the chain cannot be resolved it blocks immediately (fails closed).
- `_scrub_blocked_history` drops earlier blocked prompts and their block replies from the history before the model sees it.
- Fail-open paths (detector unreachable, empty or unparseable verdict, missing library) return a `check failed: ...` reason, and the status line reads `FAILED (not enforced)` instead of a pass.

Adding a new filter: copy the helper block, call `_record_block` instead of raising, and wrap `inlet` so it ends with `_enforce_block_if_last`. Nothing else needs to know about the other filters.

### Priority System

- Higher priority filters execute first
- Values: -200 (highest) to 100 (lowest)
- Default priorities:
  - Antivirus: -200 (highest priority)
  - Prompt Injection: -100
  - Content Safety: -1
  - Policy Violation: 0 (last block-aware filter by default, so it shows the aggregated block reply)

## API Integrations

### ClamAV Integration

The antivirus filter connects to a ClamAV daemon for virus scanning:

```
User uploads file
  ↓
Filter receives file
  ↓
Connects to ClamAV daemon
  ↓
ClamAV scans file
  ↓
Returns scan result
  ↓
Block or allow file
```

**Starting ClamAV:**
```bash
docker-compose -f docker-compose.clamav.yml up -d
```

### Safety Model API

Content safety filters can integrate with external APIs:

```
User message received
  ↓
Send to safety API
  ↓
API classifies content
  ↓
Returns safety score/classification
  ↓
Filter makes allow/block decision
```

## Debugging

### Enable Debug Mode

All filters support debug modes for troubleshooting:

**Step Debug** (Concise logs):
```
Open WebUI Admin → Filters → [Filter Name] → enable_step_debug = True
```

**Full Debug** (Detailed logs including payloads):
```
Open WebUI Admin → Filters → [Filter Name] → enable_full_debug = True
```

### Log Inspection

Debug output appears in:
- Open WebUI application logs
- Console output (if running directly)
- Docker logs (if containerized):
  ```bash
  docker logs open-webui
  ```

### Testing

Each filter includes unit tests:

```bash
# Run tests for antivirus filter
python -m pytest safety/test_clamav.py -v

# Run tests for other filters
python -m pytest safety/test_*.py -v
```

## Troubleshooting

### Antivirus Filter Issues

**ClamAV Connection Error:**
```
Error: Connection refused on localhost:3310
```
**Solution:**
1. Verify ClamAV container is running: `docker ps | grep clamav`
2. Check ClamAV logs: `docker logs clamav`
3. Verify URL in filter config matches ClamAV port

**Scan Timeout:**
```
Error: Scan timeout exceeded
```
**Solution:**
- Increase `clamav_timeout` setting (e.g., 60 seconds for large files)
- Check if ClamAV is overloaded or updating virus definitions

### Policy Violation Filter Issues

**Model Not Found:**
```
Error: Model ID 'prompt-safety-and-policy-violation-detector' not found
```
**Solution:**
1. Ensure model is available in Open WebUI
2. Update `policy_model_id` to correct model name
3. Pull model: `ollama pull <correct-model-id>`

### Performance Issues

**All Filters Running Slowly:**

1. **Reduce Priority Conflicts:**
   - Review filter priority settings
   - Spread execution across requests

2. **Increase Timeouts:**
   - Adjust `clamav_timeout` and API timeouts
   - Consider async processing for I/O operations

3. **Monitor Resources:**
   - Check CPU/memory usage: `docker stats`
   - Reduce concurrent scan threads if needed

## Security Considerations

1. **API Keys:** Store API keys securely using environment variables
2. **File Storage:** Consider using `delete_infected_files = True` for malware detection
3. **User Privacy:** Be mindful of what content gets logged in violation KBs
4. **Network Security:** Use HTTPS for external API connections
5. **Model Updates:** Keep ClamAV definitions and detection models updated

## Advanced Usage

### Custom Policy Rules

Edit filter files to add custom detection logic:

```python
# In safety_filter_company_policy_violation_v1.py
def _check_custom_policy(self, text: str) -> bool:
    # Add your custom policy logic here
    return contains_restricted_terms(text)
```

### Integration with Monitoring

Filters can emit events for monitoring systems:

```python
if __event_emitter__:
    await __event_emitter__({
        "type": "status",
        "data": {
            "description": "Violation detected",
            "done": True
        }
    })
```

### Violation Knowledge Base

Violations are logged to a knowledge base for auditing:

```python
violation_kb: str = "Malware Violations"
# Access via Open WebUI API for analytics
```

## Performance Benchmarks

Typical filter performance (per request):

| Filter | Avg Time | Notes |
|--------|----------|-------|
| Prompt Injection | 100-500ms | Model inference |
| Policy Violation | 200-800ms | Vector DB lookup + LLM |
| Antivirus (small file) | 50-200ms | <10MB file scan |
| Antivirus (large file) | 1-5s | 100MB+ file scan |
| Content Safety API | 200-1000ms | Network latency |

## Contributing

To add new filters or improve existing ones:

1. Follow the Open WebUI Filter interface
2. Implement `inlet()` and `outlet()` methods
3. Add comprehensive logging
4. Include unit tests
5. Document configuration options

## License

[Specify your license here]

## Support

For issues, questions, or contributions:
- Open an issue on the repository
- Check existing documentation
- Review filter source code comments for detailed implementation notes

## Related Resources

- [Open WebUI Documentation](https://docs.openwebui.com)
- [ClamAV Documentation](https://www.clamav.net/documents)
- [Prompt Injection Prevention](https://en.wikipedia.org/wiki/Prompt_injection)
- [Content Safety Guidelines](https://platform.openai.com/docs/guides/safety-best-practices)
