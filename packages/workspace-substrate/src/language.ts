export function languageForPath(path: string, hint?: string | null): string {
  if (hint) {
    return normalizeHint(hint);
  }

  const extension = path.split(".").pop()?.toLowerCase();
  switch (extension) {
    case "ts":
      return "typescript";
    case "tsx":
      return "typescript";
    case "js":
    case "jsx":
      return "javascript";
    case "json":
      return "json";
    case "md":
      return "markdown";
    case "rs":
      return "rust";
    case "css":
      return "css";
    case "html":
    case "htm":
      return "html";
    case "yaml":
    case "yml":
      return "yaml";
    case "sh":
    case "bash":
      return "shell";
    case "toml":
      return "ini";
    default:
      return "plaintext";
  }
}

function normalizeHint(hint: string): string {
  switch (hint) {
    case "tsx":
    case "typescript":
      return "typescript";
    case "jsx":
    case "javascript":
      return "javascript";
    case "json":
    case "markdown":
    case "rust":
    case "css":
    case "html":
    case "yaml":
    case "xml":
      return hint;
    case "shell":
      return "shell";
    case "toml":
      return "ini";
    default:
      return "plaintext";
  }
}
