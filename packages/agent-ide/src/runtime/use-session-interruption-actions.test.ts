import assert from "node:assert/strict";

import { buildClarificationPromptForTests } from "./use-session-interruption-actions.ts";

assert.equal(
  buildClarificationPromptForTests(
    {
      kind: "intent_resolution",
      question: "Where should Chat search?",
      options: [
        {
          id: "use_current_area",
          label: "Use my area",
          description:
            "Use the current area already available to this Chat session.",
        },
      ],
    },
    "use_current_area",
    "",
  ),
  "near me",
  "current-area clarification should resolve into an execution-ready locality prompt",
);

assert.equal(
  buildClarificationPromptForTests(
    {
      kind: "intent_resolution",
      question: "Should Chat broaden the search?",
      options: [
        {
          id: "broad_city_recs",
          label: "Broad city picks",
          description:
            "Give a broader city-level recommendation list instead of a tight anchor search.",
        },
      ],
    },
    "broad_city_recs",
    "",
  ),
  "Give broader city-level recommendations.",
  "structured clarification strategies should map to canonical follow-up prompts instead of raw descriptions",
);

assert.equal(
  buildClarificationPromptForTests(
    {
      kind: "intent_resolution",
      question: "What city should Chat check?",
      options: [
        {
          id: "share_city",
          label: "Share a city",
          description:
            "Tell Chat which city or area to use for the forecast.",
        },
      ],
    },
    "share_city",
    "Boston",
  ),
  "Boston",
  "typed clarification freeform input should remain authoritative",
);

console.log("use-session-interruption-actions.test.ts: ok");
