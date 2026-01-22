# Semantic Scrubber (Privacy Airlock)

The Semantic Scrubber ensures that sensitive user data (PII, Secrets) never leaves the local environment, even when using cloud-based inference models (like OpenAI).

## The Scrub-on-Export Pipeline

When an agent needs to send context (e.g., a screenshot or document) to a remote model:

1.  **Detection:**
    *   The raw text is passed to the **Local Safety Model** (a small, on-device BERT or quantized Llama).
    *   The model identifies spans of text containing PII (Names, Emails, Phone Numbers) or Secrets (API Keys, Private Keys).

2.  **Redaction:**
    *   The `SemanticScrubber` replaces the sensitive spans with placeholders:
        *   `"sk-12345..."` -> `<REDACTED:API_KEY>`
        *   `"john@doe.com"` -> `<REDACTED:EMAIL>`

3.  **Mapping:**
    *   A `RedactionMap` is generated, storing the original values and their hashes. This map stays **local**.

4.  **Transmission:**
    *   Only the scrubbed text is sent to the cloud model.

5.  **Rehydration (Optional):**
    *   If the model generates a response referencing the placeholders (e.g., *"I sent email to `<REDACTED:EMAIL>`"*), the kernel can use the map to restore the original values locally for display or execution, ensuring the cloud provider never saw the real data.