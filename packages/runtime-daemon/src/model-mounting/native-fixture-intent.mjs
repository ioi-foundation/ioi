export function nativeFixtureQueryTargetsWorkspace(queryText) {
  return /\b(repository|repo|workspace|project|codebase|source tree|inspect|files?|daemon|runtime authority|runtimeagentservice|bridge|electron workbench|studio|autopilot plan progress|plan progress|progress per)\b|\.internal\/plans\/|packages\/|apps\/|crates\//i.test(queryText);
}

export function nativeFixtureQueryNeedsWeb(queryText) {
  const text = String(queryText);
  const explicitExternalSubject = /\b(AKT|Akash|Filecoin|FIL|investment|fundamentals|market|price|crypto|stock|exchange rate|weather|news|cite|citation)\b/i.test(text);
  const currentExternalState =
    /\b(latest|current|currently|right now|today|recent)\b/i.test(text) &&
    /\b(public|web|online|market|price|investment|crypto|stock|exchange rate|weather|news|release|version|software|issue|runtime|AI|model)\b/i.test(text);
  return explicitExternalSubject || currentExternalState;
}

export function nativeFixtureQueryWorkspaceConstrained(queryText) {
  return nativeFixtureQueryTargetsWorkspace(queryText) && !nativeFixtureQueryNeedsWeb(queryText);
}

export function nativeFixtureQueryNeedsCommand(queryText) {
  const text = String(queryText || "");
  const commandLiteral = /`[^`]*(?:cargo|node|npm|pnpm|yarn|python3?|bash|sh|git|rg|make)[^`]*`/i.test(text);
  const commandPhrase = /\b(run|execute|launch)\b/i.test(text) &&
    /\b(command|shell|terminal|exit code|test|node --check|cargo test|npm test|pnpm test|yarn test)\b/i.test(text);
  return commandLiteral || commandPhrase;
}

export function nativeFixtureConversationReply(queryText) {
  const text = String(queryText || "").trim().toLowerCase();
  if (!text) return null;
  if (/^(hiya|hi|hello|hey)\b/.test(text)) {
    return "Hiya. Studio is up, daemon-routed, and ready.";
  }
  if (/\b(thanks|thank you|appreciate it)\b/.test(text)) {
    return "Anytime. I am here and keeping it tidy.";
  }
  if (/\b(sounds good|looks good|works for me|ok(?:ay)?)\b/.test(text)) {
    return "Sounds good. I will keep the next step small and verified.";
  }
  if (/\bhow are you\b/.test(text)) {
    return "I am steady and ready to help with the next turn.";
  }
  if (/\b(they can only ignore it for so long)\b/.test(text)) {
    return "Right. The useful move is to make the evidence boringly hard to dismiss.";
  }
  if (/\b(receipts? matter|run evidence matters?)\b/.test(text)) {
    return "Run evidence matters because it lets the GUI point back to daemon-owned trace proof instead of asking you to trust a projection.";
  }
  if (/\bpythagorean theorem\b/.test(text)) {
    return "The Pythagorean theorem says that in a right triangle, a squared plus b squared equals c squared.";
  }
  return null;
}
