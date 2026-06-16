export function parseMemoryCommand(prompt = "") {
  const text = String(prompt ?? "").trim();
  const remember = text.match(/^#\s*remember\s+([\s\S]+)$/i);
  if (remember?.[1]?.trim()) {
    return { kind: "remember", text: remember[1].trim() };
  }
  if (/^\/memory(?:\s+show)?\s*$/i.test(text)) {
    return { kind: "show" };
  }
  if (/^\/memory\s+disable\s*$/i.test(text)) {
    return { kind: "disable" };
  }
  if (/^\/memory\s+enable\s*$/i.test(text)) {
    return { kind: "enable" };
  }
  if (/^\/memory\s+path\s*$/i.test(text)) {
    return { kind: "path" };
  }
  const edit = text.match(/^\/memory\s+edit\s+(\S+)\s+([\s\S]+)$/i);
  if (edit?.[1] && edit?.[2]?.trim()) {
    return { kind: "edit", id: edit[1], text: edit[2].trim() };
  }
  const deletion = text.match(/^\/memory\s+(?:delete|remove|forget)\s+(\S+)\s*$/i);
  if (deletion?.[1]) {
    return { kind: "delete", id: deletion[1] };
  }
  return { kind: "none" };
}
