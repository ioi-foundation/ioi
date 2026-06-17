import type { AssistantProcessItem } from "../utils/assistantTurnProcessModel";
import { AssistantProcessRow } from "./AssistantProcessRow";

export function ToolCallRow({ item }: { item: AssistantProcessItem }) {
  return <AssistantProcessRow item={item} />;
}
