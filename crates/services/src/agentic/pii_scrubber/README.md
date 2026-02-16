# PII Scrubber (Privacy Airlock)

The PII Scrubber ensures raw secrets and PII are processed locally first. Raw content is never sent to cloud inference during PII inspection.

## Scrub-on-Export Pipeline

When context may cross an egress boundary:

1. **Deterministic Evidence Extraction**
- Local detectors identify API keys/secrets, emails, phones, SSNs, and card PANs (with validators such as Luhn).

2. **Rules-Only Routing**
- The CIM router evaluates policy and risk surface using structured evidence.

3. **Deterministic Transform**
- The scrubber replaces sensitive spans with deterministic placeholders (for example `<REDACTED:api_key>`).

4. **Boundary Enforcement**
- If transform is not available or ambiguity remains, the action is quarantined/gated according to policy.

5. **Optional Rehydration**
- Local redaction maps can re-associate placeholders to original local values when needed.
