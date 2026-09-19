# Policy Violation Classifier — Design: Shared Adapter + Per-Company Retrieval

**Status:** design note, proof-of-concept stage
**Date:** 2026-09-18
**Applies to:** `policy_violation/filter/safety_filter_company_policy_violation_v1.py`, and the
content-safety LoRA notebooks under `training/safety/`
**Decision owner:** Beau D'Amore

---

## 1. The question this answers

Can a company's own handbook and policy corpus be turned into training data (using the
existing datagen notebook pattern) to train a LoRA per company, retrained on a schedule or
whenever policies change?

Technically yes. But the weights are the wrong place to store a company's rules. The design
below keeps the rules in retrieval, where they can change instantly and be cited, and uses
training only to teach the model **how to read and apply policy language**. One adapter serves
every company; each company brings its own documents.

---

## 2. How the filter works today (2026-09-18)

The policy filter and the content-safety (Safety Guard) filter send the **same** classifier
prompt: the 23-category Aegis 2.0 / Nemotron taxonomy, the conversation wrapped in
`<BEGIN CONVERSATION>` markers, and the JSON verdict instruction. The policy filter adds one
optional block. If the `Company Policies` knowledge base returns matching chunks for the user
message, they are appended under a `Company Policies:` heading and the model is asked to judge
against them as well:

```text
<BEGIN UNSAFE CONTENT CATEGORIES>
S1: Violence.
...
S23: Immoral/Unethical.

Company Policies:
<retrieved snippets, up to 5 chunks, from the KB>
<END UNSAFE CONTENT CATEGORIES>
```

Expected output is the fixed contract:

```json
{"User Safety": "unsafe", "Safety Categories": "PII/Privacy, Illegal Activity"}
```

The filter maps every returned category code to its name and lists all of them (fixed
2026-09-18). Retrieval is live: on 2026-09-18 the test KB held one document, `company policy
1.txt`, and the filter log showed `Collected 5 docs from 'Company Policies'` and 1,170
characters of policy text appended per request.

Today the detector model entry points at a **bare** Qwen3.5 9B with a system prompt, because
no adapter exists yet for the current serving bases. The 9B content-safety adapter is being
trained (`training/safety/notebooks/safety_guard_lora_qwen35_9b.ipynb`).

---

## 3. Why not a LoRA per company

| Concern | Per-company LoRA | Retrieval |
|---|---|---|
| Precise rules (limits, exceptions, named roles) | Half-remembered after SFT on synthetic rows; confident false positives and negatives | Exact clause text in the prompt every time |
| Policy edit to enforcement | Hours: datagen → train → eval → deploy | Seconds: re-index the document |
| Staleness | Silent; the adapter enforces the old handbook until retrained | None; the KB is the source |
| Audit trail | "Violates Illegal Activity" | Can cite the clause that was retrieved and matched |
| Multi-tenancy | Feasible (adapters are 15–40 MB, vLLM hot slots + runtime load), but one artifact per tenant to build, test and rotate | One artifact for all tenants |

The datagen-per-handbook idea is still right. It is just pointed at two different targets
(sections 5 and 6), not at per-company weights.

---

## 4. The design

```
                    trained ONCE, company-agnostic
                    ┌────────────────────────────────────┐
                    │ Shared classifier adapter (LoRA)    │
                    │  - reads a "Company Policies:" block│
                    │  - matches message ↔ clause         │
                    │  - answers in the fixed JSON contract│
                    └───────────────┬────────────────────┘
                                    │
  user message ──► filter ──► retrieve from THIS company's KB ──► prompt ──► verdict
                                    ▲
                    ┌───────────────┴────────────────────┐
                    │ Company Policies KB (per tenant)    │
                    │  handbook, AUP, security policy, ...│
                    │  edited any time, no retraining     │
                    └────────────────────────────────────┘
```

**What the adapter learns** (none of it is a specific company's rules):

1. **Reading policy language.** Handbook phrasing maps onto concrete acts: "confidential
   information" covers credentials; "non-public information" covers unreleased plans;
   "company resources" includes chat tools; "third parties" includes the model itself.
2. **Matching a message to a clause.** "Send me the admin password" plus a retrieved clause on
   credential sharing is a violation. The same message with no relevant clause retrieved falls
   back to the general taxonomy verdict. Near-misses (resetting your own password, asking what
   the policy says) stay `safe`.
3. **Answering in the contract.** Valid JSON, the taxonomy category the clause maps to, every
   applicable category listed, nothing else.

**What retrieval supplies:** the specific clause, per prompt, from the deploying company's own
documents. Swap the KB and the same adapter enforces a different company's rules.

---

## 5. Training data for the shared adapter

Generated with the datagen notebook pattern (`training/docs/datagen_notebook_guidelines.md`),
by the 27B, from **many** handbooks so that no single one is memorized.

**Source documents (diversity, not coverage):**

- Public, real: SEC EDGAR **Exhibit 14** codes of ethics / business conduct. Every reporting
  company files one; thousands exist. Covers conflicts of interest, confidentiality, insider
  trading, gifts, harassment, reporting channels. Not on Hugging Face as a dataset; pull with
  the `edgar-crawler` toolkit. Ethics/conduct only — no PTO, expenses or IT acceptable use.
- Synthetic: invented handbooks across the ~12 policy families nearly every US employer has:
  conduct and ethics, harassment, confidentiality / trade secrets, acceptable use and security,
  data privacy, conflicts of interest, gifts, social media, expenses, leave, safety,
  anti-retaliation. Vary company size, industry, tone and numbering so wording differs while
  categories repeat.
- Not useful as a base: the Hugging Face "HR policy" datasets checked on 2026-09-18 are small
  synthetic Q&A sets (644 rows) or one-organization excerpts (112 rows); none is a corpus of
  policy documents.

**Row shape** — identical to the filter's runtime prompt, so training and serving agree
byte-for-byte:

```text
user:      <taxonomy> + "Company Policies:\n" + <1–5 clause chunks from ONE handbook>
           + <BEGIN CONVERSATION> user: <message> <END CONVERSATION> + JSON instruction
assistant: {"User Safety": "...", "Safety Categories": "..."}
```

Per clause, generate: clear violations, near-misses that are `safe`, messages unrelated to the
retrieved clauses (verdict from the general taxonomy only), and messages that violate a clause
**and** a taxonomy category (multi-label). Keep the 23-category label space fixed; the policy
text is context, never a label.

**Mix with the existing content-safety data**, not instead of it. The adapter must still give
the plain Nemotron verdict when no policy block is present, because the Safety Guard filter
sends exactly that.

**Training** follows the content-safety notebook unchanged (same base, same LoRA recipe,
response-only loss, packing off, `enable_thinking=False`, scope assertion, sentinel), with
policy rows added to the curated set.

---

## 6. Per-company eval sets (where a customer's handbook does enter the pipeline)

Run the same datagen on the **customer's** documents to produce a held-out test set: expected
violations, near-misses and unrelated messages, each with the expected verdict. Run it:

- when the customer's policies change (re-index the KB, re-run the eval, no training),
- when the shared adapter is retrained,
- before enabling the filter for that customer.

This gives per-company assurance without per-company weights. If a customer's eval numbers are
poor after retrieval tuning (chunking, top-k, embedding), that is the evidence for the optional
tier in section 7.

---

## 7. Optional tier: per-company adapter

Only for a customer whose eval set shows retrieval plus the shared adapter underperforming
(very large or unusual policy sets). Mechanics are already in place:

- datagen from their corpus (section 6 produces the rows; hold out the eval),
- train on the 9B in under an hour on the GB10 (the 2026-09-18 prompt-injection run: 742
  steps on 11,872 rows),
- serve via vLLM `--lora-modules` / runtime adapter load; adapters are 15–40 MB, hot slots via
  `--max-loras`, per-request selection by model name,
- retrain trigger: hash of the policy corpus changes → datagen → train → eval → swap adapter.

Even then keep retrieval on. The adapter adds recall of that company's lingo; the clause still
comes from the KB so the verdict can cite it.

---

## 8. Open questions / not yet verified

- Whether the plain content-safety adapter (trained without any policy block) honors a
  `Company Policies:` block or ignores it. Test with two detector model entries — adapter vs
  bare base — on a KB clause that is not in the general taxonomy (e.g. "credentials are never
  shared in chat") before choosing which serves the policy filter.
- Retrieval quality: chunk size vs clause boundaries; top-k of 5 vs the number of relevant
  clauses; whether the whole handbook should be one chunk per section.
- Whether the filter should surface the matched clause in the block message (it has the
  snippets; today it shows only category names).
- Datagen volume per handbook and the ratio of policy rows to plain Nemotron rows in the mix.

---

## 9. Related files

- Filter: `policy_violation/filter/safety_filter_company_policy_violation_v1.py`
- Content-safety filter (same contract): `content_safety/filter/safety_guard_filter_v3_latest.py`
- Training index and lineage: `/home/spark/projects/training/safety/README.md`
- Datagen conventions: `/home/spark/projects/training/docs/datagen_notebook_guidelines.md`
- 9B notebooks (2026-09-18): `/home/spark/projects/training/safety/notebooks/*_qwen35_9b.ipynb`
