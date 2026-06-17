import type { NodeLogic } from "../../../types/graph";

export const asRecord = (value: unknown): Record<string, any> =>
  value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, any>)
    : {};

export const parseJsonField = (value: string, fallback: unknown): unknown => {
  try {
    return JSON.parse(value || "{}");
  } catch {
    return fallback;
  }
};

export const OUTPUT_FORMAT_OPTIONS = [
  ["markdown", "Markdown"],
  ["json", "JSON"],
  ["svg", "SVG"],
  ["image", "Image"],
  ["chart", "Chart"],
  ["diff", "Diff"],
  ["patch", "Patch"],
  ["dataset", "Dataset"],
  ["message", "Message"],
  ["report", "Report"],
] as const;

export const OUTPUT_RENDERER_OPTIONS = [
  ["markdown", "Markdown"],
  ["json", "JSON"],
  ["table", "Table"],
  ["media", "Media"],
  ["diff", "Diff"],
  ["report", "Report"],
  ["patch", "Patch"],
] as const;

export const OUTPUT_DISPLAY_MODE_OPTIONS = [
  ["inline", "Inline"],
  ["canvas_preview", "Canvas preview"],
  ["table", "Table"],
  ["json", "JSON"],
  ["media", "Media"],
  ["diff", "Diff"],
  ["report", "Report"],
  ["artifact_panel", "Chat panel"],
] as const;

export const SOURCE_KIND_OPTIONS = [
  ["manual", "Manual input"],
  ["file", "File input"],
  ["media", "Media input"],
  ["dataset", "Dataset/table"],
  ["api_payload", "API payload"],
] as const;

export const MEDIA_KIND_OPTIONS = [
  ["image", "Image"],
  ["audio", "Audio"],
  ["video", "Video"],
  ["document", "Document"],
] as const;

export function defaultSourceLogicForKind(
  kind: NonNullable<NodeLogic["sourceKind"]>,
): Partial<NodeLogic> {
  switch (kind) {
    case "file":
      return {
        sourceKind: kind,
        sourcePath: "",
        fileExtension: "",
        mimeType: "application/octet-stream",
        sanitizeInput: true,
        validateMime: true,
        stripMetadata: false,
        payload: { file: "" },
        schema: { type: "object" },
      };
    case "media":
      return {
        sourceKind: kind,
        sourcePath: "input.jpg",
        fileExtension: "jpg",
        mediaKind: "image",
        mimeType: "image/jpeg",
        sanitizeInput: true,
        validateMime: true,
        stripMetadata: true,
        payload: { file: "input.jpg", mediaKind: "image", extension: "jpg" },
        schema: { type: "object" },
      };
    case "dataset":
      return {
        sourceKind: kind,
        mimeType: "application/json",
        sanitizeInput: true,
        validateMime: true,
        payload: { rows: [], schema: {} },
        schema: { type: "object" },
      };
    case "api_payload":
      return {
        sourceKind: kind,
        mimeType: "application/json",
        sanitizeInput: true,
        validateMime: true,
        payload: { body: {} },
        schema: { type: "object" },
      };
    case "manual":
    default:
      return {
        sourceKind: "manual",
        payload: { request: "Describe the input for this workflow." },
        schema: { type: "object" },
      };
  }
}
