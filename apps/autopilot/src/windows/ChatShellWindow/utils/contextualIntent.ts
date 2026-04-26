export function extractUserRequestFromContextualIntent(value: string | null | undefined): string {
  const trimmed = (value ?? "").trim();
  if (!trimmed) {
    return "";
  }

  const markers = ["[User request]", "User request:"];
  for (const marker of markers) {
    const index = trimmed.lastIndexOf(marker);
    if (index >= 0) {
      const request = trimmed
        .slice(index + marker.length)
        .replace(/^[\s:-]+/, "")
        .trim();
      if (request) {
        return request;
      }
    }
  }

  return trimmed;
}
