const STUDIO_MODE_AGENT = "agent";
const STUDIO_MODE_ASK = "ask";
const STUDIO_PERMISSION_MODE_DEFAULT = "suggest";
const STUDIO_PERMISSION_MODE_AUTO_REVIEW = "auto_local";
const STUDIO_PERMISSION_MODE_FULL_ACCESS = "never_prompt";

function stringValue(value, fallback = "") {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function normalizeStudioExecutionMode(value) {
  const normalized = stringValue(value, STUDIO_MODE_AGENT).toLowerCase().replace(/[\s-]+/g, "_");
  if (
    normalized === "ask" ||
    normalized === "chat" ||
    normalized === "chat_only" ||
    normalized === "chatonly" ||
    normalized === "direct_chat" ||
    normalized === "direct_model"
  ) {
    return STUDIO_MODE_ASK;
  }
  return STUDIO_MODE_AGENT;
}

function studioExecutionModeLabel(value) {
  return normalizeStudioExecutionMode(value) === STUDIO_MODE_ASK ? "Ask" : "Agent";
}

function normalizeStudioPermissionMode(value) {
  const normalized = stringValue(value, STUDIO_PERMISSION_MODE_DEFAULT).toLowerCase().replace(/[\s-]+/g, "_");
  if (
    normalized === "auto_review" ||
    normalized === "auto_local" ||
    normalized === "autolocal" ||
    normalized === "auto"
  ) {
    return STUDIO_PERMISSION_MODE_AUTO_REVIEW;
  }
  if (
    normalized === "full_access" ||
    normalized === "fullaccess" ||
    normalized === "never_prompt" ||
    normalized === "neverprompt" ||
    normalized === "yolo"
  ) {
    return STUDIO_PERMISSION_MODE_FULL_ACCESS;
  }
  return STUDIO_PERMISSION_MODE_DEFAULT;
}

function studioPermissionModeLabel(value) {
  switch (normalizeStudioPermissionMode(value)) {
    case STUDIO_PERMISSION_MODE_AUTO_REVIEW:
      return "Auto-review";
    case STUDIO_PERMISSION_MODE_FULL_ACCESS:
      return "Full access";
    case STUDIO_PERMISSION_MODE_DEFAULT:
    default:
      return "Default permissions";
  }
}

function studioPermissionThreadMode(value) {
  return normalizeStudioPermissionMode(value) === STUDIO_PERMISSION_MODE_FULL_ACCESS ? "yolo" : STUDIO_MODE_AGENT;
}

function studioPermissionModeOptions(selected = STUDIO_PERMISSION_MODE_DEFAULT) {
  const normalizedSelected = normalizeStudioPermissionMode(selected);
  return [
    {
      id: STUDIO_PERMISSION_MODE_DEFAULT,
      label: "Default permissions",
      description: "Ask before consequential, external, or destructive actions.",
    },
    {
      id: STUDIO_PERMISSION_MODE_AUTO_REVIEW,
      label: "Auto-review",
      description: "Allow low-risk local actions; still gate destructive or external actions.",
    },
    {
      id: STUDIO_PERMISSION_MODE_FULL_ACCESS,
      label: "Full access",
      description: "Let Agent run without approval prompts for this daemon session.",
    },
  ].map((item) => ({
    ...item,
    picked: item.id === normalizedSelected,
  }));
}

function studioPermissionDaemonMapping(value) {
  const approvalMode = normalizeStudioPermissionMode(value);
  const threadMode = studioPermissionThreadMode(approvalMode);
  return {
    approvalMode,
    approval_mode: approvalMode,
    threadMode,
    thread_mode: threadMode,
  };
}

module.exports = {
  STUDIO_MODE_AGENT,
  STUDIO_MODE_ASK,
  STUDIO_PERMISSION_MODE_AUTO_REVIEW,
  STUDIO_PERMISSION_MODE_DEFAULT,
  STUDIO_PERMISSION_MODE_FULL_ACCESS,
  normalizeStudioExecutionMode,
  normalizeStudioPermissionMode,
  studioExecutionModeLabel,
  studioPermissionDaemonMapping,
  studioPermissionModeLabel,
  studioPermissionModeOptions,
  studioPermissionThreadMode,
};
