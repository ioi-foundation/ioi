import { icons } from "./components/Icons";
import type { DropdownOption } from "./components/ChatDropdown";

export const workspaceOptions: DropdownOption[] = [
  { value: "local", label: "Local", desc: "On-device", icon: icons.laptop },
  { value: "cloud", label: "Cloud", desc: "Remote", icon: icons.cloud },
];

export const modelOptions: DropdownOption[] = [
  { value: "GPT-4o", label: "GPT-4o", desc: "OpenAI" },
  { value: "Claude 3.5", label: "Claude 3.5", desc: "Anthropic" },
  { value: "Llama 3", label: "Llama 3", desc: "Meta" },
];

export const BASE_PANEL_WIDTH = 450;
export const SIDEBAR_PANEL_WIDTH = 280;
export const ARTIFACT_PANEL_WIDTH = 468;
export const COMPACT_SIDEBAR_PANEL_WIDTH = 112;
export const COMPACT_ARTIFACT_PANEL_WIDTH = 336;

const CONTENT_PIPELINE_V2_FLAG = "AUTOPILOT_CONTENT_PIPELINE_V2";

export const CONTENT_PIPELINE_V2_ENABLED =
  String((import.meta as any).env?.[CONTENT_PIPELINE_V2_FLAG] ?? "true").toLowerCase() !==
  "false";
