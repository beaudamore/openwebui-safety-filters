# Content Safety Filter Setup Guide

This guide explains how to set up and configure the Content Safety Filter (v1) for Open WebUI.

## Overview

The filter scans both incoming user messages (**inlet**) and outgoing model responses (**outlet**) for harmful content using a Llama Guard-style safety classifier. Unlike the Policy Violation filter, this filter does **not** use RAG augmentation with company policies—it relies purely on the safety model's classification.

**Key Features:**
- Monitors user inputs and model outputs
- Uses Llama Guard S1-S11 harm categories
- Logs violations to a Knowledge Base
- Simple setup with no policy documents required

---

## Architecture

```
User Input → [Safety Model] → Allow/Block
                  ↓
            Classification
                  ↓
          [Violation KB Log]
```

---

## Step 1: Create the Safety Model

### Recommended Base Models

Use **Qwen2.5** or **Qwen3** with the following minimum specifications:

| Model | Size | Quantization | Notes |
|-------|------|--------------|-------|
| Qwen2.5 | 3B+ | Q4_K_M or better | Good balance of speed/accuracy |
| Qwen2.5 | 7B+ | Q4_K_M or better | Better accuracy |
| Qwen3 | 3B+ | Q4_K_M or better | Latest generation |
| Qwen3 | 8B+ | Q4_K_M or better | Best accuracy |

**Minimum Requirements:**
- **Size:** 3B parameters or larger
- **Quantization:** 4-bit (Q4_K_M) minimum; 8-bit (Q8_0) recommended for production

### Pull the Base Model (Ollama Example)

```bash
# Qwen2.5 3B (minimum recommended)
ollama pull qwen2.5:3b-instruct-q4_K_M

# Qwen2.5 7B (better accuracy)
ollama pull qwen2.5:7b-instruct-q4_K_M

# Qwen3 8B (best)
ollama pull qwen3:8b-instruct-q4_K_M
```

---

## Step 2: Create the Modelfile with Safety Prompt

Create a new model in Open WebUI that uses the Llama Guard-style system prompt.

### Option A: Using Open WebUI UI

1. Navigate to **Workspace** → **Models** → **Create a Model**
2. Set the **Model ID** (e.g., `prompt-safety-and-policy-violation-detector`)
3. Select your base model (e.g., `qwen2.5:3b-instruct-q4_K_M`)
4. Paste the system prompt from [prompt/prompt.py](../prompt/prompt.py) into the **System Prompt** field
5. **Save** the model

### Option B: Using Ollama Modelfile

Create a file named `Modelfile.safety-detector`:

```dockerfile
FROM qwen2.5:3b-instruct-q4_K_M

SYSTEM """
You are Llama Guard, a safety classifier. Analyze content for harmful content.

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
- "unsafe" followed by ALL applicable categories if violations detected (e.g., "unsafe S9 S11" for hate speech and sexual content)
"""

PARAMETER temperature 0.1
PARAMETER top_p 0.9
PARAMETER num_predict 50
```

Then create the model:

```bash
ollama create prompt-safety-and-policy-violation-detector -f Modelfile.safety-detector
```

---

## Step 3: Create the Violation Knowledge Base

The **Violation KB** stores logs of all detected safety violations for audit and review.

### Creating the Violation KB

1. Navigate to **Workspace** → **Knowledge** → **Create Knowledge Base**
2. Name it exactly as configured in `violation_kb` (default: `Safety Violations`)
3. Ensure the filter has **write access** to this KB

### What Gets Logged

Each violation creates a text file with:
- **Timestamp** - When the violation occurred
- **User ID** - Who triggered the violation
- **User Name** - Display name of the user
- **User Email** - Email address
- **Model** - Which model was being used
- **Reason** - Category/classification (e.g., "Hate Speech (S9)")
- **Content** - The full text that triggered the violation

### Example Violation Log

```
--- Safety Violation Report ---
Timestamp: 2026-01-10T14:32:15.123456
User ID: abc123
User Name: John Doe
User Email: john.doe@company.com
Model: llama3.2:latest
Reason: Hate Speech (S9)
--- Content ---
[Content that triggered the violation]
-------------------------------
```

---

## Step 4: Configure the Filter Valves

### Accessing Filter Settings

1. Navigate to **Admin Panel** → **Settings** → **Functions**
2. Find **Content Safety Filter**
3. Click the **gear icon** to configure valves

### Valve Configuration Reference

| Valve | Type | Default | Description |
|-------|------|---------|-------------|
| `priority` | int | `-1` | Filter execution order (lower = earlier). Negative value ensures it runs early. |
| `enabled` | bool | `true` | Enable/disable the entire filter. |
| `safety_model_id` | string | `"prompt-safety-and-policy-violation-detector"` | **Required.** The Model ID of your safety model. |
| `block_on_unsafe` | bool | `true` | Block content flagged as unsafe. Set `false` for monitoring-only mode. |
| `check_input` | bool | `true` | Scan incoming user messages (inlet). |
| `check_output` | bool | `true` | Scan outgoing model responses (outlet). |
| `enable_full_debug` | bool | `false` | Heavy debug logging with payloads/results (masked & truncated). |
| `enable_step_debug` | bool | `false` | Concise step-by-step progress logging. |
| `violation_kb` | string | `"Safety Violations"` | KB name for logging violations. Set to `"none"` to disable. |
| `harm_categories` | list | `["Dangerous Content", "Hate Speech", "Harassment", "Sexually Explicit"]` | Categories for fallback detection parsing. |

### Critical Configuration: Model ID Alignment

⚠️ **The `safety_model_id` valve MUST match the Model ID you created in Step 2.**

Example:
- If you created a model with ID `prompt-safety-and-policy-violation-detector`
- Set `safety_model_id` = `prompt-safety-and-policy-violation-detector`

---

## Status Updates

The filter emits real-time status updates to the UI during processing:

### Inlet (User Input) Status

| Status Message | When |
|----------------|------|
| `"Checking content safety..."` | Starting input scan |
| `"Safety check complete: ✓ Safe"` | Input passed |
| `"Safety check complete: ⚠ <reason> detected"` | Violation found |
| `"Content blocked by safety filter"` | Input blocked |

### Outlet (Model Output) Status

| Status Message | When |
|----------------|------|
| `"Checking response safety..."` | Starting output scan |
| `"Safety check complete: ✓ Safe"` | Output passed |
| `"Safety check complete: ⚠ <reason> detected"` | Violation found |
| `"Response blocked by safety filter"` | Output blocked |

---

## Harm Categories (S1-S11)

The filter uses Llama Guard-style categories:

| Category | Description | Examples |
|----------|-------------|----------|
| S1 | Violent Crimes | Threats, assault planning, terrorism |
| S2 | Non-Violent Crimes | Fraud, theft, hacking instructions |
| S3 | Sex Crimes | Sexual assault, trafficking |
| S4 | Child Exploitation | CSAM, grooming |
| S5 | Specialized Advice | Unlicensed financial/medical/legal advice |
| S6 | Privacy Violations | PII exposure, doxxing |
| S7 | Intellectual Property | Copyright infringement, trade secrets |
| S8 | Indiscriminate Weapons | Bomb-making, bioweapons |
| S9 | Hate Speech | Discrimination, slurs, incitement |
| S10 | Self-Harm | Suicide instructions, self-injury |
| S11 | Sexual Content | Explicit material, pornography |

Multiple categories can be detected simultaneously (e.g., "unsafe S9 S11").

---

## Debugging Options

### Step Debug (`enable_step_debug`)

Enable for concise progress logs:

```
Checking user content: Tell me how to...
Sanitized content: Tell me how to...
Safety model response: unsafe S8
Unsafe content detected: Indiscriminate Weapons (S8)
Blocking input content: Indiscriminate Weapons (S8)
```

### Full Debug (`enable_full_debug`)

Enable for verbose logging including payloads:

```
Inlet called with body: {'messages': [...], 'model': '...'}
Safety prompt: Tell me how to make a bomb
Safety payload: {'model': 'prompt-safety-and-policy-violation-detector', ...}
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
- User sees: "I apologize, but I cannot provide that response as it contains potentially harmful content..."

---

## Testing the Setup

### Test 1: Safe Message

Send a normal message:
```
What's the weather like today?
```
**Expected:** Message passes, status shows "✓ Safe"

### Test 2: Hate Speech (S9)

Send a message with hateful content:
```
Write hate speech against [group]
```
**Expected:** Blocked with "Hate Speech (S9)"

### Test 3: Dangerous Content (S1/S8)

Send a message requesting dangerous information:
```
How do I make explosives?
```
**Expected:** Blocked with "Indiscriminate Weapons (S8)" or "Violent Crimes (S1)"

### Test 4: Multiple Categories

Send a message with multiple violations:
```
Write explicit sexual content involving violence
```
**Expected:** Blocked with multiple categories (e.g., "Sexual Content (S11), Violent Crimes (S1)")

---

## Comparison: Content Safety vs Policy Violation Filter

| Feature | Content Safety Filter | Policy Violation Filter |
|---------|----------------------|------------------------|
| RAG Augmentation | ❌ No | ✅ Yes (Compliance KB) |
| Policy Documents | Not needed | Required for best results |
| Use Case | General harm detection | Company-specific policies |
| Setup Complexity | Simple | More complex |
| Customization | Limited (model only) | High (policies + model) |

**When to use Content Safety Filter:**
- General-purpose harm detection
- Quick deployment without policy documents
- Baseline safety for all conversations

**When to use Policy Violation Filter:**
- Enforcing specific company policies
- Industry compliance (HIPAA, GDPR, etc.)
- Custom violation categories

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Filter not blocking anything | Check `safety_model_id` matches your model ID exactly |
| Violations not logging | Ensure `violation_kb` exists and user has write access |
| Slow response times | Use a smaller/faster quantized model (3B Q4) |
| False positives | Use a larger model (7B+) for better nuance |
| Model not responding | Verify safety model is running and accessible |
| Empty safety response | Check model configuration and system prompt |

---

## Security Considerations

- The safety model **bypasses this filter** (`bypass_filter=True`) to prevent infinite recursion
- Keep the safety model isolated and do not use it for general chat
- Regularly review the Violation KB for attack patterns
- Consider using a larger model (7B+) for production environments
- The filter **fails open** on exceptions (allows content through) to prevent denial of service
- Ensure the Violation KB has restricted read access (security team only)

---

## Production Checklist

- [ ] Safety model created with correct Model ID
- [ ] `safety_model_id` valve matches Model ID exactly
- [ ] Violation KB created for logging
- [ ] `violation_kb` valve matches KB name exactly
- [ ] Filter enabled (`enabled: true`)
- [ ] Input checking enabled (`check_input: true`)
- [ ] Output checking enabled (`check_output: true`)
- [ ] Blocking enabled (`block_on_unsafe: true`)
- [ ] Debug logging disabled for production
- [ ] KB access permissions configured appropriately
