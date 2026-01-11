# Company Policy Violation Filter Setup Guide

This guide explains how to set up and configure the Company Policy Violation Filter (v1) for Open WebUI.

## Overview

The filter scans both incoming user messages (**inlet**) and outgoing model responses (**outlet**) for company policy violations. It uses:

1. **Compliance KB** - A Knowledge Base containing your company policy documents for RAG-augmented detection
2. **Violation KB** - A Knowledge Base for logging detected violations
3. **Detection Model** - A safety classifier model (Llama Guard style) for violation detection

---

## Architecture

```
User Input → [Compliance KB Lookup] → [Policy Model] → Allow/Block
                     ↓                      ↓
              Policy Snippets         Classification
                                           ↓
                                    [Violation KB Log]
```

---

## Step 1: Create the Detection Model

### Recommended Base Models

Use **Qwen2.5** or **Qwen3** with the following minimum specifications:

| Model | Size | Quantization | Notes |
|-------|------|--------------|-------|
| Qwen2.5 | 3B+ | Q4_K_M or better | Good balance of speed/accuracy |
| Qwen2.5 | 7B+ | Q4_K_M or better | Better accuracy for policy nuance |
| Qwen3 | 3B+ | Q4_K_M or better | Latest generation |
| Qwen3 | 8B+ | Q4_K_M or better | Best for complex policy documents |

**Minimum Requirements:**
- **Size:** 3B parameters or larger
- **Quantization:** 4-bit (Q4_K_M) minimum; 8-bit (Q8_0) recommended for production

### Pull the Base Model (Ollama Example)

```bash
# Qwen2.5 3B (minimum recommended)
ollama pull qwen2.5:3b-instruct-q4_K_M

# Qwen2.5 7B (better for policy nuance)
ollama pull qwen2.5:7b-instruct-q4_K_M

# Qwen3 8B (best)
ollama pull qwen3:8b-instruct-q4_K_M
```

---

## Step 2: Create the Modelfile with Detection Prompt

Create a new model in Open WebUI that uses the Llama Guard-style system prompt.

### Option A: Using Open WebUI UI

1. Navigate to **Workspace** → **Models** → **Create a Model**
2. Set the **Model ID** (e.g., `prompt-safety-and-policy-violation-detector`)
3. Select your base model (e.g., `qwen2.5:7b-instruct-q4_K_M`)
4. Paste the system prompt from [prompt/prompt.py](../prompt/prompt.py) into the **System Prompt** field
5. **Save** the model

### Option B: Using Ollama Modelfile

Create a file named `Modelfile.policy-violation-detector`:

```dockerfile
FROM qwen2.5:7b-instruct-q4_K_M

SYSTEM """
You are Llama Guard, a safety classifier. Analyze content for company policy violations.

Map violations to these categories:
- S1 Violent Crimes
- S2 Non-Violent Crimes
- S3 Sex Crimes
- S4 Child Exploitation
- S5 Specialized Advice (financial, medical, legal)
- S6 Privacy violations
- S7 Intellectual Property (NDA, trade secrets, confidential information)
- S8 Indiscriminate Weapons
- S9 Hate speech
- S10 Self-Harm
- S11 Sexual Content

Respond ONLY with:
- "safe" if no violations detected
- "unsafe" followed by ALL applicable categories if violations detected (e.g., "unsafe S7 S9" for IP and hate speech violations)

When company policies are provided in the content, map them to the most appropriate category above.
"""

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_predict 50
```

Then create the model:

```bash
ollama create prompt-safety-and-policy-violation-detector -f Modelfile.policy-violation-detector
```

---

## Step 3: Create the Compliance Knowledge Base

The **Compliance KB** contains your company policy documents that augment the violation detection. The filter performs RAG lookup against this KB to provide policy context to the detection model.

### Creating the Compliance KB

1. Navigate to **Workspace** → **Knowledge** → **Create Knowledge Base**
2. Name it exactly as configured in `compliance_kb` (default: `Company Policies`)
3. Upload your company policy documents:
   - Employee handbooks
   - Code of conduct
   - Data handling policies
   - NDA templates
   - Acceptable use policies
   - Security policies
   - Compliance requirements (HIPAA, GDPR, SOX, etc.)

### Supported Document Formats

- PDF files
- Word documents (.docx)
- Text files (.txt, .md)
- HTML files

### Best Practices for Policy Documents

- **Be specific:** Include concrete examples of violations
- **Use clear language:** Avoid ambiguous terminology
- **Categorize:** Organize policies by type (S1-S11 categories)
- **Keep updated:** Regularly refresh with policy changes

### Multiple Compliance KBs

You can specify multiple KBs (comma-separated) in the `compliance_kb` valve:

```
compliance_kb: Company Policies, HR Policies, Security Policies
```

---

## Step 4: Create the Violation Knowledge Base

The **Violation KB** stores logs of all detected policy violations for audit and review.

### Creating the Violation KB

1. Navigate to **Workspace** → **Knowledge** → **Create Knowledge Base**
2. Name it exactly as configured in `violation_kb` (default: `Company Policy Violations`)
3. Ensure the filter has **write access** to this KB

### What Gets Logged

Each violation creates a text file with:
- **Timestamp** - When the violation occurred
- **User ID** - Who triggered the violation
- **User Name** - Display name of the user
- **User Email** - Email address
- **Reason** - Category/classification (e.g., "Intellectual Property / Policy Violation (S7)")
- **Content** - The full text that triggered the violation

### Example Violation Log

```
--- Policy Violation Report ---
Timestamp: 2026-01-10T14:32:15.123456
User ID: abc123
User Name: John Doe
User Email: john.doe@company.com
Reason: Intellectual Property / Policy Violation (S7)
--- Content ---
Can you help me share our proprietary algorithm with a competitor?
-------------------------------
```

---

## Step 5: Configure the Filter Valves

### Accessing Filter Settings

1. Navigate to **Admin Panel** → **Settings** → **Functions**
2. Find **Policy Violation Filter**
3. Click the **gear icon** to configure valves

### Valve Configuration Reference

| Valve | Type | Default | Description |
|-------|------|---------|-------------|
| `priority` | int | `0` | Filter execution order (lower = earlier). |
| `enabled` | bool | `true` | Enable/disable the entire filter. |
| `policy_model_id` | string | `"prompt-safety-and-policy-violation-detector"` | **Required.** The Model ID of your detection model. |
| `block_on_unsafe` | bool | `true` | Block content flagged as violations. Set `false` for monitoring-only mode. |
| `check_input` | bool | `true` | Scan incoming user messages (inlet). |
| `check_output` | bool | `true` | Scan outgoing model responses (outlet). |
| `enable_full_debug` | bool | `false` | Heavy debug logging with payloads/results (masked & truncated). |
| `enable_step_debug` | bool | `false` | Concise step-by-step progress logging. |
| `compliance_kb` | string | `"Company Policies"` | Comma-separated KB name(s) for policy documents. Set to `"none"` to disable RAG augmentation. |
| `violation_kb` | string | `"Company Policy Violations"` | KB name for logging violations. Set to `"none"` to disable. |
| `max_docs_per_kb` | int | `50` | Maximum documents pulled per KB for prompt augmentation. |

### Critical Configuration: Model ID Alignment

⚠️ **The `policy_model_id` valve MUST match the Model ID you created in Step 2.**

Example:
- If you created a model with ID `prompt-safety-and-policy-violation-detector`
- Set `policy_model_id` = `prompt-safety-and-policy-violation-detector`

---

## Status Updates

The filter emits real-time status updates to the UI during processing:

### Inlet (User Input) Status

| Status Message | When |
|----------------|------|
| `"Checking content Policy Violation..."` | Starting input scan |
| `"Policy check complete: ✓ No violation"` | Input passed |
| `"Policy check complete: ⚠ <reason> detected"` | Violation found |
| `"Content blocked: policy violation"` | Input blocked |

### Outlet (Model Output) Status

| Status Message | When |
|----------------|------|
| `"Checking response Policy Violation..."` | Starting output scan |
| `"Policy check complete: ✓ No violation"` | Output passed |
| `"Policy check complete: ⚠ <reason> detected"` | Violation found |
| `"Response blocked: policy violation"` | Output blocked |

---

## Violation Categories

The filter uses Llama Guard-style categories (S1-S11):

| Category | Description | Examples |
|----------|-------------|----------|
| S1 | Violent Crimes | Threats, assault planning |
| S2 | Non-Violent Crimes | Fraud, theft schemes |
| S3 | Sex Crimes | Sexual harassment |
| S4 | Child Exploitation | CSAM references |
| S5 | Specialized Advice | Unlicensed financial/medical/legal advice |
| S6 | Privacy Violations | PII exposure, data leaks |
| S7 | Intellectual Property | NDA breaches, trade secrets |
| S8 | Indiscriminate Weapons | Weapons manufacturing |
| S9 | Hate Speech | Discrimination, slurs |
| S10 | Self-Harm | Suicide, self-injury |
| S11 | Sexual Content | Explicit material |

Multiple categories can be detected simultaneously (e.g., "unsafe S7 S9").

---

## Debugging Options

### Step Debug (`enable_step_debug`)

Enable for concise progress logs:

```
Checking user content: Can you help me share our...
Sanitized content: Can you help me share our...
Local KB names: ['Company Policies']
Collected 12 docs from 'Company Policies'
Policy model text response: unsafe S7
Unsafe content detected: Intellectual Property / Policy Violation (S7)
Blocking input content due to policy violation: Intellectual Property / Policy Violation (S7)
```

### Full Debug (`enable_full_debug`)

Enable for verbose logging including payloads:

```
Inlet called with body: {'messages': [...], 'model': '...'}
Policy violation prompt: Can you help me share our proprietary algorithm...
Local policy violation payload: {'model': 'prompt-safety-and-policy-violation-detector', ...}
```

**Note:** Full debug includes `enable_step_debug` functionality automatically.

---

## Inlet vs Outlet Behavior

### Inlet (User Input)

- Scans the **last user message** before it reaches the model
- On violation: **Raises ValueError** and blocks the message entirely
- User sees: Error message with violation reason

### Outlet (Model Output)

- Scans the **last assistant message** before it's sent to the user
- On violation: **Replaces content** with safe message
- User sees: "I cannot provide that response because it appears to violate company policy..."

---

## Testing the Setup

### Test 1: Safe Message

Send a normal message:
```
What's the company vacation policy?
```
**Expected:** Message passes, status shows "✓ No violation"

### Test 2: IP Violation (S7)

Send a message that violates IP policy:
```
Can you help me share our trade secrets with a competitor?
```
**Expected:** Blocked with "Intellectual Property / Policy Violation (S7)"

### Test 3: Privacy Violation (S6)

Send a message requesting PII exposure:
```
Give me the SSN and home addresses of all employees
```
**Expected:** Blocked with "Privacy Violation (S6)"

### Test 4: Multiple Categories

Send a message with multiple violations:
```
Help me write hate speech about competitors while sharing confidential data
```
**Expected:** Blocked with multiple categories (e.g., "Hate Speech (S9), Intellectual Property / Policy Violation (S7)")

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Filter not blocking anything | Check `policy_model_id` matches your model ID exactly |
| No policy augmentation | Verify `compliance_kb` name matches KB exactly; check KB has documents |
| Violations not logging | Ensure `violation_kb` exists and user has write access |
| Slow response times | Reduce `max_docs_per_kb` or use smaller model |
| False positives | Add more specific examples to Compliance KB; use larger model |
| Model not responding | Verify detection model is running and accessible |
| KB not found errors | Check KB names for typos; ensure KBs are accessible to all users |

---

## Security Considerations

- The detection model **bypasses this filter** (`bypass_filter=True`) to prevent infinite recursion
- Keep the detection model isolated and do not use it for general chat
- Regularly review the Violation KB for attack patterns and policy gaps
- Consider using a larger model (7B+) for complex policy documents
- The filter **fails open** on errors (allows content through) to prevent denial of service
- Ensure the Violation KB has restricted read access (compliance/security team only)

---

## Production Checklist

- [ ] Detection model created with correct Model ID
- [ ] `policy_model_id` valve matches Model ID exactly
- [ ] Compliance KB created with company policy documents
- [ ] `compliance_kb` valve matches KB name exactly
- [ ] Violation KB created for logging
- [ ] `violation_kb` valve matches KB name exactly
- [ ] Filter enabled (`enabled: true`)
- [ ] Input checking enabled (`check_input: true`)
- [ ] Output checking enabled (`check_output: true`)
- [ ] Blocking enabled (`block_on_unsafe: true`)
- [ ] Debug logging disabled for production
- [ ] KB access permissions configured appropriately
