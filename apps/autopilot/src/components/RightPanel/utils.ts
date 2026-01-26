export function extractVariables(template: string): string[] {
  const regex = /{{([^}]+)}}/g;
  const matches = new Set<string>();
  let match;
  while ((match = regex.exec(template)) !== null) {
    matches.add(match[1].trim());
  }
  return Array.from(matches);
}

export const DEFAULT_GRAPH_CONFIG = {
  env: '{\n  "env": "production",\n  "api_base": "https://api.example.com"\n}',
  policy: { maxBudget: 5.0, maxSteps: 50, timeoutMs: 30000 },
  // [NEW] Default Contract Configuration
  // Ensures new graphs have valid defaults for the SLA/Contract tab
  contract: {
    developerBond: 0,
    // Provide a helpful template to guide the user towards measurable criteria
    adjudicationRubric: "- Output MUST be a valid JSON object.\n- The response MUST directly answer the user's intent.\n- No hallucinations or broken links.",
    validationSchema: ""
  },
  meta: { name: "Untitled Graph", description: "No description" }
};