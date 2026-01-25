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
  meta: { name: "Untitled Graph", description: "No description" }
};