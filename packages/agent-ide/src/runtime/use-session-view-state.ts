import { useCallback, useReducer } from "react";
import type { SetStateAction } from "react";

export interface SessionViewState<
  TMessage,
  TInspectionView extends string,
> {
  intent: string;
  localHistory: TMessage[];
  submissionInFlight: boolean;
  submissionError: string | null;
  autoContext: boolean;
  activeDropdown: string | null;
  workspaceMode: string;
  selectedModel: string;
  planMode: boolean;
  inspectionView: TInspectionView | null;
  inspectionTargetId: string | null;
  inputFocused: boolean;
  searchQuery: string;
  isDraggingFile: boolean;
}

interface SessionViewStateAction<
  TMessage,
  TInspectionView extends string,
> {
  type: "set";
  key: keyof SessionViewState<TMessage, TInspectionView>;
  value: SetStateAction<
    SessionViewState<TMessage, TInspectionView>[keyof SessionViewState<
      TMessage,
      TInspectionView
    >]
  >;
}

export interface UseSessionViewStateOptions<
  TMessage,
  TInspectionView extends string,
> {
  initialState?: Partial<SessionViewState<TMessage, TInspectionView>>;
}

const DEFAULT_STATE: SessionViewState<never, never> = {
  intent: "",
  localHistory: [],
  submissionInFlight: false,
  submissionError: null,
  autoContext: true,
  activeDropdown: null,
  workspaceMode: "local",
  selectedModel: "GPT-4o",
  planMode: false,
  inspectionView: null,
  inspectionTargetId: null,
  inputFocused: false,
  searchQuery: "",
  isDraggingFile: false,
};

function sessionViewStateReducer<
  TMessage,
  TInspectionView extends string,
>(
  state: SessionViewState<TMessage, TInspectionView>,
  action: SessionViewStateAction<TMessage, TInspectionView>,
): SessionViewState<TMessage, TInspectionView> {
  if (action.type !== "set") {
    return state;
  }

  const current = state[action.key];
  const next =
    typeof action.value === "function"
      ? (
          action.value as (
            prev: SessionViewState<TMessage, TInspectionView>[typeof action.key],
          ) => SessionViewState<TMessage, TInspectionView>[typeof action.key]
        )(current)
      : action.value;

  if (Object.is(current, next)) {
    return state;
  }

  return {
    ...state,
    [action.key]: next,
  };
}

export function useSessionViewState<
  TMessage,
  TInspectionView extends string,
>({
  initialState,
}: UseSessionViewStateOptions<TMessage, TInspectionView> = {}) {
  const [state, dispatch] = useReducer(
    sessionViewStateReducer<TMessage, TInspectionView>,
    {
      ...(DEFAULT_STATE as SessionViewState<TMessage, TInspectionView>),
      ...initialState,
    },
  );

  const setField = useCallback(
    <K extends keyof SessionViewState<TMessage, TInspectionView>>(
      key: K,
      value: SetStateAction<SessionViewState<TMessage, TInspectionView>[K]>,
    ) => {
      dispatch({
        type: "set",
        key,
        value: value as SessionViewStateAction<TMessage, TInspectionView>["value"],
      });
    },
    [],
  );

  const setIntent = useCallback((value: SetStateAction<string>) => {
    setField("intent", value);
  }, [setField]);
  const setLocalHistory = useCallback((value: SetStateAction<TMessage[]>) => {
    setField("localHistory", value);
  }, [setField]);
  const setSubmissionInFlight = useCallback((value: SetStateAction<boolean>) => {
    setField("submissionInFlight", value);
  }, [setField]);
  const setSubmissionError = useCallback((value: SetStateAction<string | null>) => {
    setField("submissionError", value);
  }, [setField]);
  const setAutoContext = useCallback((value: SetStateAction<boolean>) => {
    setField("autoContext", value);
  }, [setField]);
  const setActiveDropdown = useCallback((value: SetStateAction<string | null>) => {
    setField("activeDropdown", value);
  }, [setField]);
  const setWorkspaceMode = useCallback((value: SetStateAction<string>) => {
    setField("workspaceMode", value);
  }, [setField]);
  const setSelectedModel = useCallback((value: SetStateAction<string>) => {
    setField("selectedModel", value);
  }, [setField]);
  const setPlanMode = useCallback((value: SetStateAction<boolean>) => {
    setField("planMode", value);
  }, [setField]);
  const setInspectionView = useCallback(
    (value: SetStateAction<TInspectionView | null>) => {
      setField("inspectionView", value);
    },
    [setField],
  );
  const setInspectionTargetId = useCallback((value: SetStateAction<string | null>) => {
    setField("inspectionTargetId", value);
  }, [setField]);
  const setInputFocused = useCallback((value: SetStateAction<boolean>) => {
    setField("inputFocused", value);
  }, [setField]);
  const setSearchQuery = useCallback((value: SetStateAction<string>) => {
    setField("searchQuery", value);
  }, [setField]);
  const setIsDraggingFile = useCallback((value: SetStateAction<boolean>) => {
    setField("isDraggingFile", value);
  }, [setField]);

  return {
    ...state,
    setField,
    setIntent,
    setLocalHistory,
    setSubmissionInFlight,
    setSubmissionError,
    setAutoContext,
    setActiveDropdown,
    setWorkspaceMode,
    setSelectedModel,
    setPlanMode,
    setInspectionView,
    setInspectionTargetId,
    setInputFocused,
    setSearchQuery,
    setIsDraggingFile,
  };
}
