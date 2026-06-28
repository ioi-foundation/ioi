#!/usr/bin/env node

const args = process.argv.slice(2);

if (args.includes("--help") || args.includes("-h")) {
  console.log(`Hypervisor Claude Code Example

Usage:
  node harness-shims/claude-code-example.mjs --provider ollama --model qwen --cd <workspace>

Options:
  --provider <PROVIDER>  Local OpenAI-compatible provider. Use ollama for this example.
  --model <MODEL>        Local model mounted by Hypervisor.
  --cd <DIR>             Workspace root admitted by the Hypervisor Daemon.
  --once <PROMPT>        Run a single prompt in non-interactive mode.
  --help                 Show this help.
`);
  process.exit(0);
}

const options = parseOptions(args);
const provider = options.provider ?? "ollama";
const model = options.model ?? "qwen";
const workspace = options.cd ?? process.cwd();

if (provider !== "ollama") {
  console.error(`Unsupported provider for this example: ${provider}`);
  process.exit(2);
}

if (!isSafeModelName(model)) {
  console.error("Model name must be shell-token safe.");
  process.exit(2);
}

if (options.once) {
  console.log(
    JSON.stringify({
      schema_version: "ioi.hypervisor.claude_code_example_once.v1",
      provider,
      model,
      workspace,
      prompt: options.once,
      mode: "local_model_mount_example",
    }),
  );
  process.exit(0);
}

console.log(
  `Hypervisor Claude Code Example ready: provider=${provider} model=${model} workspace=${workspace}`,
);
console.log("Type /exit to close this example harness session.");

process.stdin.setEncoding("utf8");
process.stdin.on("data", (chunk) => {
  for (const line of chunk.split(/\r?\n/)) {
    const input = line.trim();
    if (!input) continue;
    if (input === "/exit" || input === "exit") process.exit(0);
    console.log(`[claude-code-example:${model}] ${input}`);
  }
});

function parseOptions(values) {
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token.startsWith("--")) continue;
    const key = token.slice(2);
    const next = values[index + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = "true";
      continue;
    }
    parsed[key] = next;
    index += 1;
  }
  return parsed;
}

function isSafeModelName(value) {
  return /^[A-Za-z0-9._:/@+-]+$/.test(String(value ?? ""));
}
