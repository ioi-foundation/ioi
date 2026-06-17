export function parseArgs(argv) {
  const args = {
    contractOnly: false,
    preflight: false,
    run: false,
    outputRoot: "docs/evidence/hypervisor-app-harness-validation",
    windowName: "Autopilot Chat",
    windowTimeoutMs: 120_000,
    settleMs: 12_000,
    querySettleMs: 18_000,
    queryTimeoutMs: 240_000,
    newSessionBetweenQueries: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--contract-only") args.contractOnly = true;
    else if (arg === "--preflight") args.preflight = true;
    else if (arg === "--run") args.run = true;
    else if (arg === "--output-root")
      args.outputRoot = argv[++index] ?? args.outputRoot;
    else if (arg === "--window-name")
      args.windowName = argv[++index] ?? args.windowName;
    else if (arg === "--window-timeout-ms")
      args.windowTimeoutMs = Number(argv[++index] ?? args.windowTimeoutMs);
    else if (arg === "--settle-ms")
      args.settleMs = Number(argv[++index] ?? args.settleMs);
    else if (arg === "--query-settle-ms")
      args.querySettleMs = Number(argv[++index] ?? args.querySettleMs);
    else if (arg === "--query-timeout-ms")
      args.queryTimeoutMs = Number(argv[++index] ?? args.queryTimeoutMs);
    else if (arg === "--same-session") args.newSessionBetweenQueries = false;
    else if (arg === "--new-session-between-queries") {
      throw new Error(
        "--new-session-between-queries is disabled for retained GUI validation; the harness is same-session composer-only to avoid activity-bar/sidebar/top-chrome clicks.",
      );
    } else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!args.contractOnly && !args.preflight && !args.run) args.preflight = true;
  return args;
}
