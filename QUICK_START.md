# Quick Start Guide - Safety Filters

## 30-Second Setup

1. **Start ClamAV** (if using antivirus filter):
   ```bash
   docker-compose -f docker-compose.clamav.yml up -d
   ```

2. **Copy filters** to Open WebUI filters directory

3. **Enable in Open WebUI**:
   - Admin Panel → Settings → Filters
   - Toggle filters ON
   - Configure as needed

4. **Test**: Upload file → Should be scanned

## Essential Configuration

### Antivirus Filter
```python
clamav_url: "http://localhost:3310"      # ClamAV location
clamav_timeout: 30.0                     # seconds
block_on_detection: True                 # Block malware
delete_infected_files: False              # Keep for analysis
```

### Content Safety Filter
```python
api_url: "http://host.docker.internal:8080"  # Safety API
safety_model: "shieldgemma:2b"               # Detection model
block_on_unsafe: True                        # Block unsafe content
```

### Prompt Injection Filter
```python
injection_detection_model_id: ""      # Model for detection
block_on_unsafe: True                 # Block injections
```

### Policy Violation Filter
```python
policy_model_id: "prompt-safety-and-policy-violation-detector"
block_on_unsafe: True
check_input: True
check_output: True
```

## Common Commands

### Check ClamAV Status
```bash
docker ps | grep clamav              # Running?
docker logs clamav                   # Latest logs
docker exec clamav clamscan --version # Version
```

### Enable Debug Logging
```
Open WebUI Admin → Filters → [Filter Name]
- enable_step_debug: True    # Concise logs
- enable_full_debug: True    # Detailed logs
```

### View Violations
```
Open WebUI Admin → Knowledge Bases → [Violation KB Name]
```

### Restart Filter
```bash
# Restart Open WebUI container
docker restart open-webui

# Or disable/enable filter in UI
Admin → Filters → Toggle OFF → Toggle ON
```

## Troubleshooting Checklist

| Issue | Check |
|-------|-------|
| ClamAV won't start | `docker logs clamav` for errors |
| Files not scanned | Is `scan_attached_files` enabled? |
| Timeout errors | Increase `clamav_timeout` value |
| Can't connect | Verify `clamav_url` is correct |
| High CPU usage | Reduce `MaxThreads` in docker-compose |

## File Priority Order

Filters execute by priority (highest first):

1. **-200**: Antivirus (scan files for malware)
2. **-100**: Prompt Injection (detect attacks)
3. **0**: Content Safety & Policy (check content)

## Key Files

| File | Purpose |
|------|---------|
| `safety_filter_antivirus_antimalware.py` | Malware scanning |
| `safety_filter_guard_v1.py` | Enhanced safety filtering |
| `safety_filter_company_policy_violation_v1.py` | Policy enforcement |
| `safety_filter_prompt_injection_v*.py` | Injection prevention |
| `docker-compose.clamav.yml` | ClamAV container config |

## Health Check

To verify all filters are working:

1. Open Open WebUI
2. Check Admin → Filters → All filters show "Enabled" ✓
3. Try uploading file → Should log scan
4. Check logs for "Safety filter activated"
5. Review Admin → Knowledge Bases for violation records

## Performance Tips

- Disable unused filters
- Adjust timeouts based on file sizes
- Use step_debug (not full_debug) in production
- Monitor Docker resource usage: `docker stats`

## API Endpoints (If Running Tests)

```bash
# Test antivirus filter
POST /api/filters/antivirus/scan
{ "file_path": "path/to/file" }

# Test safety filter
POST /api/filters/safety/check
{ "content": "text to check" }
```

## Reset to Defaults

1. Open filter settings
2. Click "Reset to Defaults" button (if available)
3. Or manually restore from backup configuration

## Next Steps

- Read [README.md](README.md) for detailed overview
- Read [ANTIVIRUS_FILTER_GUIDE.md](ANTIVIRUS_FILTER_GUIDE.md) for antivirus details
- Check individual filter source code for configuration options
- Review filter logs for any issues

## Getting Help

1. Enable debug: `enable_step_debug: True`
2. Reproduce issue
3. Collect logs: `docker logs open-webui`
4. Check filter source code comments
5. Consult [README.md](README.md) troubleshooting section

---

**Version**: 1.0.0  
**Last Updated**: January 2025
