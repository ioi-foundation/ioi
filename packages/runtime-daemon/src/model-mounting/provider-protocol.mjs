export function estimateTokens(input, output) {
  const inputTokens = Math.max(1, Math.ceil(String(input).length / 4));
  const outputTokens = Math.max(1, Math.ceil(String(output).length / 4));
  return {
    prompt_tokens: inputTokens,
    completion_tokens: outputTokens,
    total_tokens: inputTokens + outputTokens,
  };
}
