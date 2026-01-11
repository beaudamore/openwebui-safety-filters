# Open WebUI Safety Filters

A comprehensive collection of content filtering and safety modules for Open WebUI. These filters provide protection against malware, harmful content, policy violations, and prompt injection attacks.

## Author

**Beau D'Amore**  
[www.damore.ai](https://www.damore.ai)

## Overview

This repository contains multiple safety filter implementations designed to protect Open WebUI deployments by scanning user inputs and model outputs for various threats and policy violations. All filters follow the Open WebUI Filter interface specification.

### Available Filters

1. **Antivirus/Antimalware Filter** (`safety_filter_antivirus_antimalware.py`)
   - Scans file uploads with ClamAV for viruses and malware
   - Integrates with ClamAV daemon for real-time threat detection
   - Automatically blocks infected files and logs violations

2. **Content Safety Filter** (`safety/api/safety_filter_api.py`)
   - Filters user inputs and model outputs for harmful content
   - Uses external safety API for content classification
   - Detects: Dangerous Content, Hate Speech, Harassment, Sexually Explicit material

3. **Enhanced Safety Filter** (`safety_filter_guard_v1.py`)
   - Advanced safety filtering with policy augmentation
   - Integrates with Open WebUI's internal chat completion system
   - Supports optional policy augmentation via direct API calls
   - Includes comprehensive logging and debugging capabilities

4. **Policy Violation Filter** (`safety_filter_company_policy_violation_v1.py`)
   - Detects potential company policy violations in user input and model output
   - Uses Open WebUI's internal chat system and vector database
   - Customizable policy rules and violation detection thresholds
   - Tracks violation history per user

5. **Prompt Injection Filters** (Multiple versions: v1, v1.1, v2)
   - Detects and prevents prompt injection attacks
   - Uses semantic analysis for advanced attack detection
   - Progressive versions with improved detection capabilities
   - Configurable detection models and sensitivity levels

## Installation

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
```

### Antivirus/Antimalware Filter

**Configuration Options:**

```python
scan_attached_files: bool = True
    # Enable scanning of files attached to messages

clamav_url: str = "http://localhost:3310"
    # ClamAV daemon endpoint URL

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
api_url: str = "http://host.docker.internal:8080"
    # Safety API endpoint URL

api_key: str = ""
    # API authentication key

safety_model: str = "shieldgemma:2b"
    # Model used for safety classification

check_input: bool = True
    # Check user input messages

check_output: bool = True
    # Check model output responses

block_on_unsafe: bool = True
    # Block unsafe content

harm_categories: List[str]
    # Categories to detect (see filter file for full list)
```

### Policy Violation Filter

**Configuration Options:**

```python
policy_model_id: str = "prompt-safety-and-policy-violation-detector"
    # Model ID for policy violation detection

block_on_unsafe: bool = True
    # Block policy violations

check_input: bool = True
    # Check user input

check_output: bool = True
    # Check model output

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

enable_full_debug: bool = False
    # Detailed debugging logs

enable_step_debug: bool = False
    # Step-by-step progress logs
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
    
    async def outlet(self, body: dict, **kwargs) -> dict:
        """Process outgoing model responses"""
        pass
```

### Execution Flow

1. **Inlet Phase**: User message enters → Filter checks input → Decision to allow/block
2. **Outlet Phase**: Model response ready → Filter checks output → Decision to allow/block
3. **Violation Logging**: Detected violations logged to knowledge base
4. **User Status**: User may be flagged for review based on violation count

### Priority System

- Higher priority filters execute first
- Values: -200 (highest) to 100 (lowest)
- Default priorities:
  - Antivirus: -200 (highest priority)
  - Prompt Injection: -100
  - Other filters: 0

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
