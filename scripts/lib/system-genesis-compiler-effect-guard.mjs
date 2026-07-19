export const SYSTEM_GENESIS_EFFECT_GUARDS = Object.freeze([
  Object.freeze({
    id: "filesystem",
    pattern:
      /\b(?:std::fs|tokio::fs|File::(?:create|open)|OpenOptions|remove_file|write_all)\b/u,
  }),
  Object.freeze({
    id: "network",
    pattern:
      /\b(?:std::net|tokio::net|TcpStream|UdpSocket|reqwest|hyper::client)\b/u,
  }),
  Object.freeze({
    id: "clock",
    pattern: /\b(?:std::time|SystemTime|Instant::now|Utc::now|Local::now)\b/u,
  }),
  Object.freeze({
    id: "random",
    pattern: /\b(?:rand::|getrandom|Uuid::new_v[47]|random::<|thread_rng)\b/u,
  }),
  Object.freeze({
    id: "environment",
    pattern: /\b(?:std::env|env!|option_env!)\b/u,
  }),
  Object.freeze({
    id: "process",
    pattern: /\b(?:std::process|tokio::process|Command::new|process::exit)\b/u,
  }),
  Object.freeze({
    id: "daemon",
    pattern: /\b(?:ioi_daemon|hypervisor_daemon|DaemonClient|DaemonHandle)\b/u,
  }),
  Object.freeze({
    id: "wallet",
    pattern: /\b(?:wallet_network|wallet::|WalletClient|WalletAuthority)\b/u,
  }),
  Object.freeze({
    id: "agentgres",
    pattern: /\b(?:agentgres|Agentgres|sqlx::|diesel::)\b/u,
  }),
]);

const TEST_BOUNDARY = "\n#[cfg(test)]";

export function productionCompilerSource(source) {
  const boundary = source.indexOf(TEST_BOUNDARY);
  if (boundary === -1) {
    throw new Error("system genesis compiler lacks a #[cfg(test)] boundary");
  }
  return source.slice(0, boundary);
}

export function compilerEffectViolations(source) {
  const productionSource = productionCompilerSource(source);
  return SYSTEM_GENESIS_EFFECT_GUARDS.filter(({ pattern }) =>
    pattern.test(productionSource),
  ).map(({ id }) => id);
}
