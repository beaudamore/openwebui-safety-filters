# Antivirus/Antimalware Filter for Open WebUI - Detailed Guide

## Overview

The Antivirus/Antimalware Filter provides real-time malware and virus detection for file uploads in Open WebUI. It integrates with ClamAV, an open-source antivirus engine, to scan files before they are processed or stored.

## Features

- **Real-time Scanning**: Scans file uploads immediately using ClamAV daemon
- **Virus & Malware Detection**: Comprehensive threat detection across file types
- **Configurable Response**: Block files, delete infected uploads, or log violations
- **Violation Tracking**: Tracks malware detections per user and enforces user status changes
- **File Preservation**: Stores scan results in Open WebUI knowledge base for audit trails
- **Comprehensive Logging**: Step-by-step and full debug modes for troubleshooting
- **Async Processing**: Non-blocking file scanning using thread pool execution

## Installation & Setup

### Step 1: Deploy ClamAV

The filter requires a running ClamAV daemon instance.

**Deploy ClamAV with Docker Compose**

```bash
cd /path/to/filters
docker-compose -f docker-compose.clamav.yml up -d
```

Verify ClamAV is running:
```bash
docker ps | grep clamav
docker logs clamav  # Check startup messages
```

Wait for startup completion (approximately 5 minutes for initial database download):
```bash
docker logs clamav | grep "Listening"
```

> **Automatic Updates**: The ClamAV Docker image includes `freshclam` which automatically updates virus definitions every 2 hours. The `clamav-db` volume persists updates across container restarts. No manual intervention required.
>
> Verify updates are working:
> ```bash
> docker logs clamav | grep -i "update\|download"
> ```

### Step 1b: Install clamd in Open WebUI Container

The filter requires the `clamd` Python library. Install it into your Open WebUI container:

```bash
docker exec -it open-webui pip install clamd
```

> **Note**: Replace `open-webui` with your container name if different.

### Step 2: Configure Filter in Open WebUI

1. Open Open WebUI Admin Panel
2. Navigate to **Settings → Filters**
3. Find and enable **"Antivirus/Antimalware Filter"**
4. Configure the following settings:

## Configuration Parameters

### Basic Settings

| Parameter | Default | Description |
|-----------|---------|-------------|
| `enabled` | `True` | Enable/disable the filter |
| `priority` | `-200` | Execution priority (higher = earlier) |
| `scan_attached_files` | `True` | Scan files attached to messages |

### ClamAV Connection

```python
clamav_url: str = "http://localhost:3310"
```
- **Purpose**: ClamAV daemon endpoint URL
- **Examples**:
  - Local: `http://localhost:3310`
  - Docker network: `http://clamav:3310`
  - Remote server: `https://clamav.example.com:3310`

```python
clamav_timeout: float = 30.0
```
- **Purpose**: Maximum time to wait for scan completion (seconds)
- **Adjust for**:
  - Small files (<10MB): 10-15 seconds
  - Medium files (10-100MB): 30-60 seconds
  - Large files (>100MB): 120+ seconds

### File Handling

```python
block_on_detection: bool = True
```
- **True**: Block and reject infected files
- **False**: Allow infected files (not recommended for security)

```python
delete_infected_files: bool = False
```
- **True**: Automatically delete detected malware from storage
- **False**: Keep files for analysis (requires manual cleanup)
- **Recommendation**: Enable for production environments

### Violation Tracking

```python
violation_kb: str = "Malware Violations"
```
- **Purpose**: Knowledge base name for storing violation records
- **Default**: Creates/uses "Malware Violations" KB
- **Access**: Admin panel → Knowledge Bases → [Name]

```python
max_violations_count: int = 3
```
- **Purpose**: Maximum violations before user status changes to "pending"
- **Effect**: After N violations, user requires admin review
- **Use Case**: Prevent repeated malware upload attempts

### Debugging

```python
enable_step_debug: bool = False
```
- **Purpose**: Log concise progress information
- **Output**: Startup, file received, scan started/completed
- **Use when**: Troubleshooting connection issues

```python
enable_full_debug: bool = False
```
- **Purpose**: Log detailed information including file info and scan results
- **Output**: File hashes, sizes, scan metadata (truncated for security)
- **Use when**: Detailed troubleshooting or auditing

## How It Works

### File Upload Flow

```
1. User uploads file to Open WebUI
   ↓
2. Filter's inlet() method receives file
   ↓
3. Check: Is filter enabled?
   ├─ No → Pass file through
   └─ Yes → Continue to step 4
   ↓
4. Check: Is scan_attached_files enabled?
   ├─ No → Pass file through
   └─ Yes → Continue to step 5
   ↓
5. Check: Is file in Files model already?
   ├─ Yes → Skip scan (prevent duplicate scans)
   └─ No → Continue to step 6
   ↓
6. Connect to ClamAV daemon
   ↓
7. Read file in chunks (SpooledTemporaryFile)
   ↓
8. Send to ClamAV for scanning
   ↓
9. Receive scan result (clean/infected/error)
   ↓
10. If infected:
    ├─ Log violation to knowledge base
    ├─ Check violation count
    ├─ If > max_violations_count → Mark user as "pending"
    ├─ If delete_infected_files → Delete from storage
    └─ If block_on_detection → Raise error/reject file
   ↓
11. If clean:
    ├─ Log clean scan to knowledge base
    └─ Allow file through
   ↓
12. File continues to Open WebUI processing
```

### Scan Result Examples

**Clean File:**
```
File: document.pdf
Status: ✓ Clean
Hash: a1b2c3d4e5f6...
Size: 2.5 MB
Duration: 0.45 seconds
```

**Infected File:**
```
File: malware.exe
Status: ⚠ Infected
Threat: Trojan.Generic
Hash: x1y2z3a4b5c6...
Size: 512 KB
Duration: 0.12 seconds
Action: Blocked (block_on_detection=True)
```

**ClamAV Connection Error:**
```
Status: ⚠ Error
Message: Connection refused to ClamAV at http://localhost:3310
Duration: 2.0 seconds (timeout)
Fallback: Allow file through
```

## Usage Examples

### Example 1: Basic Configuration (Development)

```python
# Minimal security setup for testing
clamav_url: str = "http://localhost:3310"
clamav_timeout: float = 30.0
block_on_detection: bool = True
delete_infected_files: bool = False
max_violations_count: int = 5
enable_full_debug: bool = True  # For debugging
```

### Example 2: Production Security Setup

```python
# Strict security setup for production
clamav_url: str = "http://clamav:3310"  # Using Docker network
clamav_timeout: float = 60.0  # Generous timeout
block_on_detection: bool = True
delete_infected_files: bool = True  # Auto-delete malware
max_violations_count: int = 3  # Quick user suspension
enable_full_debug: bool = False  # For performance
enable_step_debug: bool = True  # Minimal logging
```

### Example 3: Large File Handling

```python
# Optimized for large file uploads
clamav_url: str = "http://clamav-pool:3310"  # Load-balanced
clamav_timeout: float = 300.0  # 5 minutes for large files
scan_attached_files: bool = True
max_violations_count: int = 2  # Strict for serious threats
```

## Testing

### Unit Test: EICAR Test File

Test file provided: `safety/eicar.txt`

**About EICAR:**
- Standard antivirus test file
- Recognized as "malware" by all antivirus engines
- Completely harmless (plain text)
- Used to verify detection without real malware

**Run Test:**
```bash
# Upload eicar.txt through Open WebUI interface
# Expected: File is detected as malware and blocked
```

**Test Script:**
```bash
python safety/test_clamav.py -v
```

### Manual Testing

**Test 1: Verify ClamAV Connection**
```bash
# From command line
telnet localhost 3310
# Should connect successfully
```

**Test 2: Verify Scan**
```bash
# Copy EICAR test file
cp safety/eicar.txt /tmp/test_eicar.txt

# Scan with clamscan (if installed)
clamscan /tmp/test_eicar.txt
# Expected output: Infected with EICAR-STANDARD-NOT-A-VIRUS
```

**Test 3: Test Filter Directly**
```python
# In Python console
from safety_filter_antivirus_antimalware import Filter
import asyncio

filter_instance = Filter()
# Manually call methods with test data
```

## Troubleshooting

### Issue 1: "Connection refused to ClamAV"

**Symptoms:**
```
Error: Connection refused on localhost:3310
```

**Solutions:**

1. **Verify ClamAV is running:**
   ```bash
   docker ps | grep clamav
   ```
   If not running:
   ```bash
   docker-compose -f docker-compose.clamav.yml up -d
   ```

2. **Verify port is accessible:**
   ```bash
   # Test connection
   timeout 2 bash -c '</dev/tcp/localhost/3310' && echo "Port open" || echo "Port closed"
   ```

3. **Check ClamAV startup:**
   ```bash
   docker logs clamav | tail -20
   # Look for: "Listening on port 3310"
   ```

4. **Verify network connectivity (Docker):**
   ```bash
   # If Open WebUI in Docker, verify it can reach ClamAV
   docker exec open-webui ping clamav
   ```

### Issue 2: "Scan timeout exceeded"

**Symptoms:**
```
Error: Timeout waiting for ClamAV scan result
```

**Solutions:**

1. **Increase timeout:**
   - Filter settings → `clamav_timeout: float = 60.0` (or higher)
   - Based on file size: Large files (>100MB) may need 120+ seconds

2. **Check ClamAV load:**
   ```bash
   docker stats clamav
   # Look for high CPU/memory usage
   ```

3. **Reduce concurrent scans:**
   - Edit `docker-compose.clamav.yml`
   - Set `CLAMD_CONF_MaxThreads=2` (reduce from 4)
   - Restart: `docker-compose restart clamav`

4. **Check log for issues:**
   ```bash
   docker logs clamav | grep -i error
   ```

### Issue 3: "ClamAV returning errors"

**Symptoms:**
```
Error: ClamAV returned error code X
```

**Common Error Codes:**
- **Code 1**: Infected file (expected)
- **Code 2**: Scan error (check logs)
- **Code 3**: Out of memory or database issue

**Solutions:**

1. **Update virus definitions:**
   ```bash
   docker exec clamav freshclam
   ```

2. **Restart ClamAV:**
   ```bash
   docker-compose -f docker-compose.clamav.yml restart clamav
   ```

3. **Check disk space:**
   ```bash
   docker exec clamav df -h
   # Ensure at least 1GB free for ClamAV DB
   ```

### Issue 4: "Files not being scanned"

**Symptoms:**
- Uploads accepted without scanning
- No log entries from filter

**Solutions:**

1. **Verify filter is enabled:**
   - Open WebUI Admin → Filters → Check if filter is toggled on

2. **Check scan_attached_files setting:**
   - Filter settings → `scan_attached_files: bool = True`

3. **Enable debug mode:**
   - Set `enable_step_debug: bool = True`
   - Upload file and check logs
   - Look for: "Scanning file" messages

4. **Check violation KB exists:**
   - Knowledge Bases should contain violation entries
   - If empty, check logs for KB creation errors

### Issue 5: "Performance degradation"

**Symptoms:**
- Slow file uploads
- High CPU usage on ClamAV

**Solutions:**

1. **Monitor resource usage:**
   ```bash
   docker stats clamav open-webui
   ```

2. **Adjust scan parameters:**
   - Set `clamav_timeout: float = 45.0` (slightly lower for responsiveness)
   - Configure `MaxScanSize=500M` in docker-compose.yml

3. **Limit file size:**
   - Add file size validation before scanning
   - Skip scanning for known-safe file types

4. **Use file type whitelist:**
   ```python
   # In filter, add before scan:
   allowed_types = ['.pdf', '.txt', '.docx', '.jpg']
   if file.name.endswith(tuple(allowed_types)):
       return body  # Skip scan
   ```

## Monitoring & Logging

### Access Violation Records

All scans (clean and infected) are logged to the Knowledge Base:

```
Open WebUI Admin Panel
  ↓
Knowledge Bases
  ↓
"Malware Violations" (default name)
  ↓
View all scan records with timestamps
```

### Example Log Entry

```
Timestamp: 2025-01-08T10:30:45Z
User: john_doe
File: presentation.pdf
Hash: sha256:a1b2c3d4e5f6...
Status: CLEAN
Duration: 0.35s

---

Timestamp: 2025-01-08T10:35:12Z
User: jane_smith
File: malware.exe
Hash: sha256:x1y2z3a4b5c6...
Status: INFECTED
Threat: Trojan.Generic
Duration: 0.12s
Action: BLOCKED (delete_infected_files=True)
```

### Enable Debug Logging

**Step-by-Step Debug** (Recommended for troubleshooting):
```
Enable: enable_step_debug = True
Output: "[FILTER] Step 1: File received" "Step 2: Connecting to ClamAV" etc.
Log file: Open WebUI logs directory
```

**Full Debug** (For detailed analysis):
```
Enable: enable_full_debug = True
Output: File hashes, sizes, complete scan results (truncated)
Log file: Open WebUI logs directory
Warning: May impact performance
```

### View Logs

```bash
# Docker deployment
docker logs -f open-webui | grep -i "antivirus\|clamav\|malware"

# Docker compose
docker-compose logs -f open-webui

# Standalone
tail -f /path/to/open-webui/logs/app.log
```

## Performance Optimization

### Scanning Time Estimates

| File Size | Scan Time | Notes |
|-----------|-----------|-------|
| <1MB | 50-150ms | Typical small files |
| 1-10MB | 100-300ms | Documents, images |
| 10-100MB | 500-2000ms | Large files, archives |
| >100MB | 5-30s | May hit timeout |

### Optimization Tips

1. **Pre-filter by file type:**
   ```python
   # Skip scanning for known-safe types
   safe_extensions = ['.txt', '.pdf', '.jpg', '.png']
   ```

2. **Implement file size limits:**
   ```python
   max_scan_size = 100 * 1024 * 1024  # 100MB
   if file.size > max_scan_size:
       skip_scan = True
   ```

3. **Use streaming for large files:**
   - Filter already uses `SpooledTemporaryFile`
   - Reads in chunks to minimize memory

4. **Increase ClamAV resources (if slow):**
   ```yaml
   # In docker-compose.clamav.yml
   CLAMD_CONF_MaxThreads=8  # Increase from 4
   ```

## Security Best Practices

1. **Always enable block_on_detection** for production
2. **Set delete_infected_files=True** to prevent storage of malware
3. **Monitor violation KB regularly** for patterns
4. **Keep virus definitions updated** - ClamAV updates automatically
5. **Use HTTPS for remote ClamAV** if not on local network
6. **Limit file upload sizes** to prevent DoS
7. **Review user violations regularly** - suspend repeated offenders

## Advanced Configuration

### Custom File Type Handling

Add to filter code:
```python
def _should_skip_scan(self, filename: str) -> bool:
    """Skip scanning for certain file types"""
    skip_extensions = ['.txt', '.md', '.pdf']
    return any(filename.endswith(ext) for ext in skip_extensions)
```

### Custom Violation Response

Modify violation handling:
```python
async def _log_violation(self, user_id: str, file_name: str):
    """Custom violation logging logic"""
    # Send alert to security system
    # Update user risk score
    # Generate incident report
```

### Integration with Monitoring

Emit custom events:
```python
if __event_emitter__:
    await __event_emitter__({
        "type": "custom_event",
        "data": {
            "event": "malware_detected",
            "file": filename,
            "threat": threat_name,
            "timestamp": datetime.now().isoformat()
        }
    })
```

## API Reference

### Filter Class Methods

#### `async def inlet(body: dict, **kwargs) -> dict`
- **Purpose**: Process incoming user messages with attached files
- **Parameters**:
  - `body`: Message body with files
  - `__user__`: User information
  - `__event_emitter__`: Event callback function
- **Returns**: Modified body (with or without files)
- **Raises**: ValueError if scan fails and blocking is enabled

#### `async def _scan_file_with_clamav(file_bytes: bytes, filename: str) -> tuple`
- **Purpose**: Perform actual ClamAV scan
- **Parameters**:
  - `file_bytes`: File content
  - `filename`: Original filename
- **Returns**: (is_clean: bool, details: dict)

#### `async def _log_scan_result(user_id: str, file_name: str, result: dict) -> None`
- **Purpose**: Log scan results to knowledge base
- **Parameters**:
  - `user_id`: User ID from request context
  - `file_name`: Scanned file name
  - `result`: Scan result dictionary
- **Returns**: None

## Uninstalling/Disabling

### Disable Filter Only
```
Open WebUI Admin → Filters → Antivirus/Antimalware → Toggle OFF
```

### Remove ClamAV Container
```bash
docker-compose -f docker-compose.clamav.yml down
# Remove volumes (virus DB):
docker volume rm filters_clamav-db filters_clamav-logs
```

### Remove Filter Files
```bash
rm safety_filter_antivirus_antimalware.py
rm -rf safety/__pycache__
```

## Support & Troubleshooting Resources

- **ClamAV Docs**: https://www.clamav.net/documents
- **Open WebUI Docs**: https://docs.openwebui.com
- **Filter Logs**: Check Open WebUI application logs
- **Issues**: Create issue with debug logs enabled

## Version History

**v1.0.0** (Current)
- Initial release
- ClamAV integration
- Violation tracking
- Full debug support

---

For more information, see the main [README.md](README.md) for the filters project.
