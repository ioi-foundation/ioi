import type { MouseEvent } from "react";
import { getCurrentWindow, PhysicalPosition } from "../../services/hypervisorHostBridge";

export function isHypervisorClientRuntime(): boolean {
  return (
    typeof window !== "undefined" &&
    "__HYPERVISOR_HOST_BRIDGE__" in window
  );
}

export function isInteractiveWindowTarget(target: EventTarget | null): boolean {
  if (!(target instanceof Element)) return false;
  return target.closest("button, input, select, textarea, a, [role='button']") !== null;
}

export function startHostWindowDrag(event: MouseEvent<HTMLElement>): void {
  if (!isHypervisorClientRuntime()) return;
  if (event.button !== 0) return;
  if (event.detail > 1) return;
  if (isInteractiveWindowTarget(event.target)) return;

  event.preventDefault();

  const appWindow = getCurrentWindow();
  const startScreenX = event.screenX;
  const startScreenY = event.screenY;
  let origin: { x: number; y: number } | null = null;
  let active = true;

  const stopDragging = () => {
    active = false;
    document.removeEventListener("mousemove", moveWindow);
    document.removeEventListener("mouseup", stopDragging);
  };

  const moveWindow = (moveEvent: globalThis.MouseEvent) => {
    if (!active || !origin) return;
    const nextX = Math.round(origin.x + moveEvent.screenX - startScreenX);
    const nextY = Math.round(origin.y + moveEvent.screenY - startScreenY);
    void appWindow.setPosition(new PhysicalPosition(nextX, nextY)).catch(() => {
      stopDragging();
    });
  };

  document.addEventListener("mousemove", moveWindow);
  document.addEventListener("mouseup", stopDragging, { once: true });

  void appWindow.outerPosition().then((position) => {
    if (!active) return;
    origin = { x: position.x, y: position.y };
  }).catch(() => {
    stopDragging();
  });
}
