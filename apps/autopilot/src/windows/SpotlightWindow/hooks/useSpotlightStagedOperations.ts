import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import {
  getSessionOperatorRuntime,
  type SessionOperatorRuntime,
} from "../../../services/sessionRuntime";
import type { LocalEngineStagedOperation } from "../../../types";

type SpotlightStagedOperationsState = {
  operations: LocalEngineStagedOperation[];
  loading: boolean;
  busyOperationId: string | null;
  message: string | null;
  error: string | null;
};

const INITIAL_STATE: SpotlightStagedOperationsState = {
  operations: [],
  loading: false,
  busyOperationId: null,
  message: null,
  error: null,
};

async function loadOperations(
  runtime: SessionOperatorRuntime,
): Promise<LocalEngineStagedOperation[]> {
  const snapshot = await runtime.getLocalEngineSnapshot();
  return [...snapshot.stagedOperations].sort(
    (left, right) => right.createdAtMs - left.createdAtMs,
  );
}

export function useSpotlightStagedOperations() {
  const [state, setState] = useState<SpotlightStagedOperationsState>(INITIAL_STATE);

  const refreshOperations = useCallback(async (showLoading: boolean = false) => {
    if (showLoading) {
      setState((current) => ({
        ...current,
        loading: true,
        message: null,
        error: null,
      }));
    }

    try {
      const operations = await loadOperations(getSessionOperatorRuntime());
      setState((current) => ({
        ...current,
        operations,
        loading: false,
        error: null,
      }));
    } catch (error) {
      setState((current) => ({
        ...current,
        loading: false,
        error: String(error),
      }));
    }
  }, []);

  useEffect(() => {
    void refreshOperations(true);
  }, [refreshOperations]);

  useEffect(() => {
    let active = true;
    const unlistenPromise = listen("local-engine-updated", () => {
      if (!active) {
        return;
      }
      void refreshOperations(false);
    });

    return () => {
      active = false;
      void unlistenPromise.then((unlisten) => unlisten());
    };
  }, [refreshOperations]);

  const runAction = useCallback(
    async (
      operationId: string,
      successMessage: string,
      action: (runtime: SessionOperatorRuntime) => Promise<void>,
    ) => {
      setState((current) => ({
        ...current,
        busyOperationId: operationId,
        message: null,
        error: null,
      }));

      try {
        const runtime = getSessionOperatorRuntime();
        await action(runtime);
        const operations = await loadOperations(runtime);
        setState((current) => ({
          ...current,
          operations,
          loading: false,
          busyOperationId: null,
          message: successMessage,
          error: null,
        }));
      } catch (error) {
        setState((current) => ({
          ...current,
          busyOperationId: null,
          error: String(error),
        }));
      }
    },
    [],
  );

  const promoteOperation = useCallback(
    async (operationId: string) =>
      runAction(
        operationId,
        "Staged operation promoted into the live Local Engine queue.",
        (runtime) => runtime.promoteLocalEngineOperation(operationId),
      ),
    [runAction],
  );

  const removeOperation = useCallback(
    async (operationId: string) =>
      runAction(
        operationId,
        "Staged operation removed from Spotlight.",
        (runtime) => runtime.removeLocalEngineOperation(operationId),
      ),
    [runAction],
  );

  return {
    ...state,
    refreshOperations,
    promoteOperation,
    removeOperation,
  };
}
