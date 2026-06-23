// Pure string-list helpers extracted from harness-workflow/core.ts. Leaf module
// (no harness-workflow dependencies) so core.ts and sibling validators can share
// them without a cycle. Behavior is unchanged from the in-core definitions.

export function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return Array.from(
    new Set(
      values.filter(
        (value): value is string =>
          typeof value === "string" && value.length > 0,
      ),
    ),
  );
}

export function sortedUniqueStrings(
  values: Array<string | null | undefined>,
): string[] {
  return uniqueStrings(values).sort();
}
