type StudioFileIconKind =
  | "file"
  | "image"
  | "markdown"
  | "json"
  | "yaml"
  | "html"
  | "typescript"
  | "javascript"
  | "rust"
  | "vite";

export type StudioFileTypeIconContext = "explorer" | "tab";

export function fileIconKind(name: string): StudioFileIconKind {
  const lower = name.toLowerCase();

  if (
    lower.endsWith(".png") ||
    lower.endsWith(".jpg") ||
    lower.endsWith(".jpeg") ||
    lower.endsWith(".gif") ||
    lower.endsWith(".webp") ||
    lower.endsWith(".ico") ||
    lower.endsWith(".bmp")
  ) {
    return "image";
  }

  if (lower.endsWith(".md") || lower.endsWith(".mdx")) {
    return "markdown";
  }

  if (lower.startsWith("vite.config.")) {
    return "vite";
  }

  if (lower === "cargo.toml" || lower.endsWith(".rs") || lower.endsWith(".toml")) {
    return "rust";
  }

  if (lower.endsWith(".json")) {
    return "json";
  }

  if (lower.endsWith(".yaml") || lower.endsWith(".yml")) {
    return "yaml";
  }

  if (lower.endsWith(".html") || lower.endsWith(".htm")) {
    return "html";
  }

  if (lower.endsWith(".ts") || lower.endsWith(".tsx")) {
    return "typescript";
  }

  if (lower.endsWith(".js") || lower.endsWith(".jsx")) {
    return "javascript";
  }

  return "file";
}

export function StudioFileTypeIcon({
  name,
  context = "explorer",
}: {
  name: string;
  context?: StudioFileTypeIconContext;
}) {
  const kind = fileIconKind(name);
  const sizeClass = context === "tab" ? "is-tab" : "is-explorer";

  if (kind === "file") {
    return (
      <span
        className={`studio-file-sheet ${sizeClass}`}
        aria-hidden="true"
      />
    );
  }

  if (kind === "markdown") {
    return (
      <svg
        className={`studio-file-icon ${sizeClass} is-markdown`}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <circle cx="8" cy="8" r="6" stroke="currentColor" strokeWidth="1.4" />
        <path d="M8 7v4" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" />
        <circle cx="8" cy="4.6" r="0.8" fill="currentColor" />
      </svg>
    );
  }

  if (kind === "image") {
    return (
      <svg
        className={`studio-file-icon ${sizeClass} is-image`}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <rect x="2.2" y="3" width="11.6" height="10" rx="1.5" stroke="currentColor" strokeWidth="1.2" />
        <circle cx="6" cy="6.2" r="1.1" fill="currentColor" />
        <path
          d="M3.8 11.5 6.6 8.8a.7.7 0 0 1 .98 0l1.6 1.54a.7.7 0 0 0 .96.03l1.02-.9a.7.7 0 0 1 .94.03l1.04 1.02"
          stroke="currentColor"
          strokeWidth="1.2"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    );
  }

  if (kind === "rust") {
    return (
      <svg
        className={`studio-file-icon ${sizeClass} is-rust`}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M8 3.2 9.1 2.6l1 1.1 1.42-.1.42 1.43 1.28.63-.33 1.39.92 1.08-.92 1.08.33 1.39-1.28.63-.42 1.43-1.42-.1-1 1.1L8 12.8l-1.1.6-1-1.1-1.42.1-.42-1.43-1.28-.63.33-1.39-.92-1.08.92-1.08-.33-1.39 1.28-.63.42-1.43 1.42.1 1-1.1L8 3.2Z"
          stroke="currentColor"
          strokeWidth="1.1"
          strokeLinejoin="round"
        />
        <circle cx="8" cy="8" r="2" fill="currentColor" />
      </svg>
    );
  }

  if (kind === "vite") {
    return (
      <svg
        className={`studio-file-icon ${sizeClass} is-vite`}
        width="14"
        height="14"
        viewBox="0 0 16 16"
        fill="none"
        aria-hidden="true"
      >
        <path
          d="M8.9 1.8 4.9 8.3h2.34L6.6 14.2l4.5-7.06H8.74L8.9 1.8Z"
          fill="currentColor"
        />
      </svg>
    );
  }

  const label =
    kind === "json"
      ? "{}"
      : kind === "yaml"
        ? "!"
        : kind === "html"
          ? "<>"
          : kind === "typescript"
            ? "TS"
            : "JS";

  return (
    <span
      className={`studio-file-badge ${sizeClass} is-${kind}`}
      aria-hidden="true"
    >
      {label}
    </span>
  );
}
