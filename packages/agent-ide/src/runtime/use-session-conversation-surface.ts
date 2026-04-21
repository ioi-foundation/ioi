import { useCallback, useEffect, useRef, useState } from "react";
import type {
  DependencyList,
  Dispatch,
  RefObject,
  SetStateAction,
} from "react";

export interface UseSessionConversationScrollOptions {
  scrollContainerRef: RefObject<HTMLElement | null>;
  autoScrollDeps: DependencyList;
  nearBottomThresholdPx?: number;
}

export function useSessionConversationScroll({
  scrollContainerRef,
  autoScrollDeps,
  nearBottomThresholdPx = 100,
}: UseSessionConversationScrollOptions) {
  const isUserAtBottomRef = useRef(true);
  const [showScrollButton, setShowScrollButton] = useState(false);

  useEffect(() => {
    const container = scrollContainerRef.current;
    if (!container) {
      return;
    }

    const handleScroll = () => {
      const { scrollTop, scrollHeight, clientHeight } = container;
      const distanceFromBottom = scrollHeight - scrollTop - clientHeight;
      const isNearBottom = distanceFromBottom < nearBottomThresholdPx;

      isUserAtBottomRef.current = isNearBottom;
      setShowScrollButton(!isNearBottom);
    };

    container.addEventListener("scroll", handleScroll);
    return () => container.removeEventListener("scroll", handleScroll);
  }, [nearBottomThresholdPx, scrollContainerRef]);

  useEffect(() => {
    if (scrollContainerRef.current && isUserAtBottomRef.current) {
      scrollContainerRef.current.scrollTo({
        top: scrollContainerRef.current.scrollHeight,
        behavior: "smooth",
      });
    }
  }, [scrollContainerRef, ...autoScrollDeps]);

  const scrollToBottom = useCallback(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTo({
        top: scrollContainerRef.current.scrollHeight,
        behavior: "smooth",
      });
      isUserAtBottomRef.current = true;
      setShowScrollButton(false);
    }
  }, [scrollContainerRef]);

  return {
    showScrollButton,
    scrollToBottom,
  };
}

export interface UseSessionDeferredFocusOptions {
  focusRef: RefObject<{ focus: () => void } | null>;
  focusDeps?: DependencyList;
  enabled?: boolean;
  delayMs?: number;
}

export function useSessionDeferredFocus({
  focusRef,
  focusDeps = [],
  enabled = true,
  delayMs = 0,
}: UseSessionDeferredFocusOptions) {
  useEffect(() => {
    if (!enabled) {
      return;
    }

    let cancelled = false;
    const timeoutIds: number[] = [];

    const attemptFocus = () => {
      if (cancelled) {
        return;
      }

      const target = focusRef.current;
      if (!target) {
        return;
      }

      const activeElement = document.activeElement;
      const shouldAvoidStealingFocus =
        activeElement instanceof HTMLElement &&
        activeElement !== document.body &&
        activeElement !== target;

      if (shouldAvoidStealingFocus) {
        return;
      }

      target.focus();
    };

    const scheduleFocusAttempt = (timeoutMs: number) => {
      const timeoutId = window.setTimeout(() => {
        window.requestAnimationFrame(attemptFocus);
      }, timeoutMs);
      timeoutIds.push(timeoutId);
    };

    [delayMs, delayMs + 120, delayMs + 320].forEach(scheduleFocusAttempt);

    return () => {
      cancelled = true;
      timeoutIds.forEach((timeoutId) => window.clearTimeout(timeoutId));
    };
  }, [delayMs, enabled, focusRef, ...focusDeps]);
}

export interface UseSessionChatArtifactDrawerOptions {
  enabled: boolean;
  artifactAvailable: boolean;
  artifactExpected?: boolean;
  activeSessionId?: string | null;
  fallbackSessionId?: string | null;
  setVisible: Dispatch<SetStateAction<boolean>>;
}

export function useSessionChatArtifactDrawer({
  enabled,
  artifactAvailable,
  artifactExpected = false,
  activeSessionId = null,
  fallbackSessionId = null,
  setVisible,
}: UseSessionChatArtifactDrawerOptions) {
  const autoOpenedSessionIdRef = useRef<string | null>(null);

  useEffect(() => {
    if (!enabled) {
      return;
    }

    if (!artifactAvailable && !artifactExpected) {
      setVisible(false);
      if (!activeSessionId) {
        autoOpenedSessionIdRef.current = null;
      }
      return;
    }

    const nextSessionId = activeSessionId || fallbackSessionId || null;
    if (!nextSessionId) {
      return;
    }

    if (autoOpenedSessionIdRef.current === nextSessionId) {
      return;
    }

    autoOpenedSessionIdRef.current = nextSessionId;
    setVisible(true);
  }, [
    activeSessionId,
    artifactAvailable,
    artifactExpected,
    enabled,
    fallbackSessionId,
    setVisible,
  ]);
}
