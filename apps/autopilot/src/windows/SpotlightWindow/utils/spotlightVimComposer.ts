type SpotlightVimTextObject =
  | "around_word"
  | "inner_word"
  | "around_double_quote"
  | "inner_double_quote"
  | "around_single_quote"
  | "inner_single_quote"
  | "around_paren"
  | "inner_paren"
  | "around_bracket"
  | "inner_bracket"
  | "around_brace"
  | "inner_brace";
type SpotlightVimTextObjectPrefix = "around" | "inner";
export type PendingVimMotionPrefix = "g" | null;
type SpotlightVimMotionPrefix = Exclude<PendingVimMotionPrefix, null>;

export interface PendingVimOperatorState {
  kind: "change" | "delete";
  textObjectPrefix: SpotlightVimTextObjectPrefix | null;
}

export type PendingVimOperator = PendingVimOperatorState | null;

type SpotlightVimMotion =
  | "back_word"
  | "end_word"
  | "line_end"
  | "line_indent"
  | "line_start"
  | "word";

export type SpotlightVimRepeatableCommand =
  | {
      count?: number;
      kind: "delete_char";
    }
  | {
      count?: number;
      change: boolean;
      kind: "document_edit";
      target: "document_end" | "line_start";
      targetLineNumber?: number;
    }
  | {
      count?: number;
      change: boolean;
      kind: "line_edit";
    }
  | {
      count?: number;
      change: boolean;
      kind: "motion_edit";
      motion: SpotlightVimMotion;
    }
  | {
      count?: number;
      change: boolean;
      kind: "text_object_edit";
      textObject: SpotlightVimTextObject;
    };

export interface SpotlightVimKeyInput {
  altKey: boolean;
  code: string;
  ctrlKey: boolean;
  key: string;
  metaKey: boolean;
  shiftKey: boolean;
}

export interface SpotlightVimNormalState {
  lastCommand: SpotlightVimRepeatableCommand | null;
  pendingMotionPrefix: SpotlightVimMotionPrefix | null;
  pendingOperator: PendingVimOperator;
  pendingCount: number | null;
  selectionEnd: number;
  selectionStart: number;
  value: string;
}

export interface SpotlightVimNormalResult {
  enterInsertMode: boolean;
  handled: boolean;
  lastCommand: SpotlightVimRepeatableCommand | null;
  pendingMotionPrefix: SpotlightVimMotionPrefix | null;
  pendingOperator: PendingVimOperator;
  pendingCount: number | null;
  selectionEnd: number;
  selectionStart: number;
  value: string;
}

function clampCursor(value: string, cursor: number) {
  return Math.max(0, Math.min(cursor, value.length));
}

function commandCount(count: number | null | undefined) {
  return Math.max(1, count ?? 1);
}

function storedCommandCount(count: number | null | undefined) {
  const normalized = commandCount(count);
  return normalized > 1 ? normalized : undefined;
}

function commandCountPatch(count: number | null | undefined) {
  const storedCount = storedCommandCount(count);
  return storedCount === undefined ? {} : { count: storedCount };
}

function repeatCursorMotion(
  value: string,
  cursor: number,
  count: number | null | undefined,
  step: (currentValue: string, currentCursor: number) => number,
) {
  let nextCursor = clampCursor(value, cursor);
  for (let index = 0; index < commandCount(count); index += 1) {
    nextCursor = step(value, nextCursor);
  }
  return nextCursor;
}

function lineStartCursor(value: string, cursor: number) {
  const safeCursor = clampCursor(value, cursor);
  const previousBreak = value.lastIndexOf("\n", Math.max(0, safeCursor - 1));
  return previousBreak === -1 ? 0 : previousBreak + 1;
}

function lineStartForLineNumber(value: string, lineNumber: number) {
  let currentLine = 1;
  let index = 0;
  const targetLine = Math.max(1, Math.trunc(lineNumber));

  while (currentLine < targetLine && index < value.length) {
    const nextBreak = value.indexOf("\n", index);
    if (nextBreak === -1) {
      return index;
    }
    index = nextBreak + 1;
    currentLine += 1;
  }

  return index;
}

function lineEndCursor(value: string, cursor: number) {
  const safeCursor = clampCursor(value, cursor);
  const nextBreak = value.indexOf("\n", safeCursor);
  return nextBreak === -1 ? value.length : nextBreak;
}

function lineIndentCursor(value: string, cursor: number) {
  const start = lineStartCursor(value, cursor);
  const end = lineEndCursor(value, cursor);
  let index = start;

  while (index < end && /[ \t]/.test(value[index])) {
    index += 1;
  }

  return index;
}

function lineIndentText(value: string, cursor: number) {
  const start = lineStartCursor(value, cursor);
  const indent = lineIndentCursor(value, cursor);
  return value.slice(start, indent);
}

function nextLineCursor(value: string, cursor: number) {
  const safeCursor = clampCursor(value, cursor);
  const start = lineStartCursor(value, safeCursor);
  const end = lineEndCursor(value, safeCursor);
  if (end >= value.length) {
    return safeCursor;
  }
  const nextStart = end + 1;
  const nextEnd = lineEndCursor(value, nextStart);
  const column = safeCursor - start;
  return Math.min(nextEnd, nextStart + column);
}

function previousLineCursor(value: string, cursor: number) {
  const safeCursor = clampCursor(value, cursor);
  const start = lineStartCursor(value, safeCursor);
  if (start <= 0) {
    return safeCursor;
  }
  const previousEnd = start - 1;
  const previousStart = lineStartCursor(value, previousEnd);
  const column = safeCursor - start;
  return Math.min(previousEnd, previousStart + column);
}

function classifyVimMotionChar(character: string) {
  if (/\s/.test(character)) {
    return "space";
  }

  if (/[A-Za-z0-9_]/.test(character)) {
    return "word";
  }

  return "symbol";
}

function nextWordCursor(value: string, cursor: number) {
  let index = clampCursor(value, cursor);

  if (index >= value.length) {
    return value.length;
  }

  let currentKind = classifyVimMotionChar(value[index]);
  if (currentKind === "space") {
    while (index < value.length && classifyVimMotionChar(value[index]) === "space") {
      index += 1;
    }
    return index;
  }

  while (index < value.length && classifyVimMotionChar(value[index]) === currentKind) {
    index += 1;
  }

  while (index < value.length && classifyVimMotionChar(value[index]) === "space") {
    index += 1;
  }

  return index;
}

function previousWordCursor(value: string, cursor: number) {
  let index = clampCursor(value, cursor);

  if (index <= 0) {
    return 0;
  }

  index -= 1;
  while (index >= 0 && classifyVimMotionChar(value[index]) === "space") {
    index -= 1;
  }

  if (index < 0) {
    return 0;
  }

  const currentKind = classifyVimMotionChar(value[index]);
  while (index > 0 && classifyVimMotionChar(value[index - 1]) === currentKind) {
    index -= 1;
  }

  return index;
}

function endOfWordCursor(value: string, cursor: number) {
  let index = clampCursor(value, cursor);

  if (index >= value.length) {
    return value.length;
  }

  while (index < value.length && classifyVimMotionChar(value[index]) === "space") {
    index += 1;
  }

  if (index >= value.length) {
    return value.length;
  }

  const currentKind = classifyVimMotionChar(value[index]);
  while (index < value.length && classifyVimMotionChar(value[index]) === currentKind) {
    index += 1;
  }

  return index;
}

function wordEndMotionCursor(value: string, cursor: number) {
  const endExclusive = endOfWordCursor(value, cursor);
  if (endExclusive <= 0) {
    return 0;
  }
  return Math.max(0, endExclusive - 1);
}

function wordObjectRange(value: string, cursor: number) {
  let start = clampCursor(value, cursor);

  if (!value.length) {
    return null;
  }

  while (start < value.length && classifyVimMotionChar(value[start]) === "space") {
    start += 1;
  }

  if (start >= value.length) {
    return null;
  }

  const kind = classifyVimMotionChar(value[start]);
  let end = start;

  while (start > 0 && classifyVimMotionChar(value[start - 1]) === kind) {
    start -= 1;
  }

  while (end < value.length && classifyVimMotionChar(value[end]) === kind) {
    end += 1;
  }

  return {
    start,
    end,
  };
}

function textObjectRange(
  value: string,
  cursor: number,
  textObject: SpotlightVimTextObject,
) {
  if (textObject === "inner_word" || textObject === "around_word") {
    const baseRange = wordObjectRange(value, cursor);
    if (!baseRange) {
      return null;
    }

    if (textObject === "inner_word") {
      return baseRange;
    }

    let start = baseRange.start;
    let end = baseRange.end;

    if (end < value.length && /\s/.test(value[end])) {
      while (end < value.length && /\s/.test(value[end])) {
        end += 1;
      }
      return {
        start,
        end,
      };
    }

    while (start > 0 && /\s/.test(value[start - 1])) {
      start -= 1;
    }

    return {
      start,
      end,
    };
  }

  if (
    textObject === "inner_double_quote" ||
    textObject === "around_double_quote" ||
    textObject === "inner_single_quote" ||
    textObject === "around_single_quote"
  ) {
    const quoteChar =
      textObject === "inner_double_quote" || textObject === "around_double_quote"
        ? '"'
        : "'";
    const quotePositions: number[] = [];
    for (let index = 0; index < value.length; index += 1) {
      if (value[index] !== quoteChar) {
        continue;
      }
      if (index > 0 && value[index - 1] === "\\") {
        continue;
      }
      quotePositions.push(index);
    }

    for (let index = 0; index + 1 < quotePositions.length; index += 2) {
      const start = quotePositions[index];
      const end = quotePositions[index + 1];
      if (cursor < start || cursor > end) {
        continue;
      }
      return textObject === "inner_double_quote" ||
          textObject === "inner_single_quote"
        ? { start: start + 1, end }
        : { start, end: end + 1 };
    }
    return null;
  }

  const openChar =
    textObject === "inner_paren" || textObject === "around_paren"
      ? "("
      : textObject === "inner_bracket" || textObject === "around_bracket"
        ? "["
        : "{";
  const closeChar =
    textObject === "inner_paren" || textObject === "around_paren"
      ? ")"
      : textObject === "inner_bracket" || textObject === "around_bracket"
        ? "]"
        : "}";
  let start = -1;
  let depth = 0;
  for (let index = clampCursor(value, cursor); index >= 0; index -= 1) {
    if (value[index] === closeChar) {
      depth += 1;
      continue;
    }
    if (value[index] !== openChar) {
      continue;
    }
    if (depth === 0) {
      start = index;
      break;
    }
    depth -= 1;
  }

  if (start === -1) {
    return null;
  }

  let end = -1;
  depth = 0;
  for (let index = start + 1; index < value.length; index += 1) {
    if (value[index] === openChar) {
      depth += 1;
      continue;
    }
    if (value[index] !== closeChar) {
      continue;
    }
    if (depth === 0) {
      end = index;
      break;
    }
    depth -= 1;
  }

  if (end === -1 || cursor > end) {
    return null;
  }

  return textObject === "inner_paren" ||
      textObject === "inner_bracket" ||
      textObject === "inner_brace"
    ? { start: start + 1, end }
    : { start, end: end + 1 };
}

function textObjectFromKeyInput(
  prefix: SpotlightVimTextObjectPrefix,
  keyInput: SpotlightVimKeyInput,
): SpotlightVimTextObject | null {
  if (!keyInput.altKey && !keyInput.ctrlKey && !keyInput.metaKey) {
    if (!keyInput.shiftKey && keyInput.code === "KeyW") {
      return prefix === "inner" ? "inner_word" : "around_word";
    }
    if (keyInput.key === '"') {
      return prefix === "inner"
        ? "inner_double_quote"
        : "around_double_quote";
    }
    if (keyInput.key === "'") {
      return prefix === "inner"
        ? "inner_single_quote"
        : "around_single_quote";
    }
    if (keyInput.key === "(" || keyInput.key === ")") {
      return prefix === "inner" ? "inner_paren" : "around_paren";
    }
    if (keyInput.key === "[" || keyInput.key === "]") {
      return prefix === "inner" ? "inner_bracket" : "around_bracket";
    }
    if (keyInput.key === "{" || keyInput.key === "}") {
      return prefix === "inner" ? "inner_brace" : "around_brace";
    }
  }

  return null;
}

function handledResult(
  state: SpotlightVimNormalState,
  patch: Partial<SpotlightVimNormalResult>,
): SpotlightVimNormalResult {
  const selectionStart = clampCursor(
    patch.value ?? state.value,
    patch.selectionStart ?? state.selectionStart,
  );
  const selectionEnd = clampCursor(
    patch.value ?? state.value,
    patch.selectionEnd ?? state.selectionEnd,
  );

  return {
    handled: true,
    value: patch.value ?? state.value,
    selectionStart,
    selectionEnd,
    pendingOperator:
      patch.pendingOperator === undefined
        ? state.pendingOperator
        : patch.pendingOperator,
    pendingMotionPrefix:
      patch.pendingMotionPrefix === undefined
        ? state.pendingMotionPrefix
        : patch.pendingMotionPrefix,
    pendingCount:
      patch.pendingCount === undefined ? state.pendingCount : patch.pendingCount,
    lastCommand:
      patch.lastCommand === undefined ? state.lastCommand : patch.lastCommand,
    enterInsertMode: patch.enterInsertMode ?? false,
  };
}

function unhandledResult(state: SpotlightVimNormalState): SpotlightVimNormalResult {
  return {
    handled: false,
    value: state.value,
    selectionStart: clampCursor(state.value, state.selectionStart),
    selectionEnd: clampCursor(state.value, state.selectionEnd),
    pendingOperator: state.pendingOperator,
    pendingMotionPrefix: state.pendingMotionPrefix,
    pendingCount: state.pendingCount,
    lastCommand: state.lastCommand,
    enterInsertMode: false,
  };
}

function currentLineDeleteRange(value: string, cursor: number) {
  const start = lineStartCursor(value, cursor);
  const end = lineEndCursor(value, cursor);

  if (end < value.length && value[end] === "\n") {
    return {
      start,
      end: end + 1,
      cursor: start,
    };
  }

  if (start > 0) {
    return {
      start: start - 1,
      end,
      cursor: start - 1,
    };
  }

  return {
    start,
    end,
    cursor: start,
  };
}

function motionRange(
  value: string,
  motion: SpotlightVimMotion,
  selectionStart: number,
  selectionEnd: number,
) {
  switch (motion) {
    case "back_word":
      return {
        start: previousWordCursor(value, selectionStart),
        end: selectionEnd,
      };
    case "end_word":
      return {
        start: selectionStart,
        end: endOfWordCursor(value, selectionEnd),
      };
    case "line_end":
      return {
        start: selectionStart,
        end: lineEndCursor(value, selectionEnd),
      };
    case "line_indent": {
      const target = lineIndentCursor(value, selectionStart);
      return target <= selectionStart
        ? {
            start: target,
            end: selectionEnd,
          }
        : {
            start: selectionStart,
            end: target,
          };
    }
    case "line_start": {
      const target = lineStartCursor(value, selectionStart);
      return target <= selectionStart
        ? {
            start: target,
            end: selectionEnd,
          }
        : {
            start: selectionStart,
            end: target,
          };
    }
    case "word":
    default:
      return {
        start: selectionStart,
        end: nextWordCursor(value, selectionEnd),
      };
  }
}

function applyRepeatableCommandOnce(
  state: SpotlightVimNormalState,
  command: SpotlightVimRepeatableCommand,
): SpotlightVimNormalResult {
  const selectionStart = clampCursor(state.value, state.selectionStart);
  const selectionEnd = clampCursor(state.value, state.selectionEnd);
  const leftEdge = Math.min(selectionStart, selectionEnd);
  const rightEdge = Math.max(selectionStart, selectionEnd);
  const collapsed = selectionStart === selectionEnd;

  if (command.kind === "delete_char") {
    const deleteStart = leftEdge;
    const deleteEnd = collapsed ? Math.min(state.value.length, rightEdge + 1) : rightEdge;
    const nextValue =
      deleteEnd > deleteStart
        ? `${state.value.slice(0, deleteStart)}${state.value.slice(deleteEnd)}`
        : state.value;
    return handledResult(state, {
      value: nextValue,
      selectionStart: deleteStart,
      selectionEnd: deleteStart,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      lastCommand: command,
    });
  }

  if (command.kind === "motion_edit") {
    const range = motionRange(state.value, command.motion, leftEdge, rightEdge);
    const nextValue =
      range.end > range.start
        ? `${state.value.slice(0, range.start)}${state.value.slice(range.end)}`
        : state.value;
    return handledResult(state, {
      value: nextValue,
      selectionStart: range.start,
      selectionEnd: range.start,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      lastCommand: command,
      enterInsertMode: command.change,
    });
  }

  if (command.kind === "document_edit") {
    const targetCursor =
      command.target === "document_end"
        ? state.value.length
        : lineStartForLineNumber(state.value, command.targetLineNumber ?? 1);
    const range =
      targetCursor <= leftEdge
        ? {
            start: targetCursor,
            end: rightEdge,
          }
        : {
            start: leftEdge,
            end: targetCursor,
          };
    const nextValue =
      range.end > range.start
        ? `${state.value.slice(0, range.start)}${state.value.slice(range.end)}`
        : state.value;
    return handledResult(state, {
      value: nextValue,
      selectionStart: range.start,
      selectionEnd: range.start,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      lastCommand: command,
      enterInsertMode: command.change,
    });
  }

  if (command.kind === "text_object_edit") {
    const range = textObjectRange(state.value, leftEdge, command.textObject);
    if (!range) {
      return handledResult(state, {
        pendingOperator: null,
        pendingMotionPrefix: null,
        pendingCount: null,
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
        lastCommand: command,
      });
    }
    const nextValue = `${state.value.slice(0, range.start)}${state.value.slice(range.end)}`;
    return handledResult(state, {
      value: nextValue,
      selectionStart: range.start,
      selectionEnd: range.start,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      lastCommand: command,
      enterInsertMode: command.change,
    });
  }

  if (command.change) {
    const start = lineStartCursor(state.value, leftEdge);
    const end = lineEndCursor(state.value, leftEdge);
    const indent = lineIndentCursor(state.value, leftEdge);
    const nextValue = `${state.value.slice(0, start)}${state.value.slice(
      start,
      indent,
    )}${state.value.slice(end)}`;
    return handledResult(state, {
      value: nextValue,
      selectionStart: indent,
      selectionEnd: indent,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      lastCommand: command,
      enterInsertMode: true,
    });
  }

  const range = currentLineDeleteRange(state.value, leftEdge);
  const nextValue = `${state.value.slice(0, range.start)}${state.value.slice(range.end)}`;
  return handledResult(state, {
    value: nextValue,
    selectionStart: range.cursor,
    selectionEnd: range.cursor,
    pendingOperator: null,
    pendingMotionPrefix: null,
    pendingCount: null,
    lastCommand: command,
  });
}

function applyRepeatableCommand(
  state: SpotlightVimNormalState,
  command: SpotlightVimRepeatableCommand,
): SpotlightVimNormalResult {
  const repetitions = commandCount(command.count);
  let currentState = {
    ...state,
    pendingOperator: null,
    pendingMotionPrefix: null,
    pendingCount: null,
  };
  let lastResult = handledResult(state, {
    pendingOperator: null,
    pendingMotionPrefix: null,
    pendingCount: null,
    lastCommand: command,
  });

  for (let index = 0; index < repetitions; index += 1) {
    const nextResult = applyRepeatableCommandOnce(currentState, {
      ...command,
      count: 1,
    });
    lastResult = nextResult;
    currentState = {
      value: nextResult.value,
      selectionStart: nextResult.selectionStart,
      selectionEnd: nextResult.selectionEnd,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      lastCommand: command,
    };
    if (nextResult.enterInsertMode) {
      break;
    }
  }

  return handledResult(state, {
    value: currentState.value,
    selectionStart: currentState.selectionStart,
    selectionEnd: currentState.selectionEnd,
    pendingOperator: null,
    pendingMotionPrefix: null,
    pendingCount: null,
    lastCommand: command,
    enterInsertMode: lastResult.enterInsertMode,
  });
}

export function applySpotlightVimNormalKey(
  state: SpotlightVimNormalState,
  keyInput: SpotlightVimKeyInput,
): SpotlightVimNormalResult {
  const isModifierFreeKey =
    !keyInput.altKey && !keyInput.ctrlKey && !keyInput.metaKey;
  const isLowercaseMotionKey = isModifierFreeKey && !keyInput.shiftKey;
  const leftEdge = Math.min(
    clampCursor(state.value, state.selectionStart),
    clampCursor(state.value, state.selectionEnd),
  );
  const rightEdge = Math.max(
    clampCursor(state.value, state.selectionStart),
    clampCursor(state.value, state.selectionEnd),
  );
  const collapsed = state.selectionStart === state.selectionEnd;
  const pendingOperator = state.pendingOperator;
  const pendingMotionPrefix = state.pendingMotionPrefix;
  const pendingCount = state.pendingCount;

  if (
    isModifierFreeKey &&
    !keyInput.shiftKey &&
    /^[0-9]$/.test(keyInput.key)
  ) {
    const digit = Number(keyInput.key);
    if (digit !== 0 || pendingCount !== null) {
      return handledResult(state, {
        pendingCount: (pendingCount ?? 0) * 10 + digit,
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }
  }

  if (pendingMotionPrefix === "g") {
    if (isLowercaseMotionKey && keyInput.code === "KeyG") {
      if (pendingOperator !== null) {
        return applyRepeatableCommand(state, {
          kind: "document_edit",
          change: pendingOperator.kind === "change",
          target: "line_start",
          targetLineNumber: pendingCount ?? 1,
        });
      }

      const targetLineStart = lineStartForLineNumber(state.value, pendingCount ?? 1);
      const cursor = lineIndentCursor(state.value, targetLineStart);
      return handledResult(state, {
        pendingOperator: null,
        pendingMotionPrefix: null,
        pendingCount: null,
        selectionStart: cursor,
        selectionEnd: cursor,
      });
    }

    if (isModifierFreeKey) {
      return handledResult(state, {
        pendingOperator: null,
        pendingMotionPrefix: null,
        pendingCount: null,
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }
  }

  if (pendingOperator !== null) {
    const change = pendingOperator.kind === "change";
    const pendingTextObjectPrefix = pendingOperator.textObjectPrefix;

    if (!pendingTextObjectPrefix && isLowercaseMotionKey && keyInput.code === "KeyI") {
      return handledResult(state, {
        pendingOperator: {
          kind: pendingOperator.kind,
          textObjectPrefix: "inner",
        },
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }

    if (!pendingTextObjectPrefix && isLowercaseMotionKey && keyInput.code === "KeyA") {
      return handledResult(state, {
        pendingOperator: {
          kind: pendingOperator.kind,
          textObjectPrefix: "around",
        },
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }

    if (!pendingTextObjectPrefix && isLowercaseMotionKey && keyInput.code === "KeyG") {
      return handledResult(state, {
        pendingOperator,
        pendingMotionPrefix: "g",
        pendingCount,
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }

    if (pendingTextObjectPrefix) {
      const textObject = textObjectFromKeyInput(pendingTextObjectPrefix, keyInput);
      if (textObject) {
        return applyRepeatableCommand(state, {
          ...commandCountPatch(pendingCount),
          kind: "text_object_edit",
          textObject,
          change,
        });
      }
    }

    if (isLowercaseMotionKey && keyInput.code === "KeyW") {
      return applyRepeatableCommand(state, {
        ...commandCountPatch(pendingCount),
        kind: "motion_edit",
        motion: "word",
        change,
      });
    }

    if (isLowercaseMotionKey && keyInput.code === "KeyE") {
      return applyRepeatableCommand(state, {
        ...commandCountPatch(pendingCount),
        kind: "motion_edit",
        motion: "end_word",
        change,
      });
    }

    if (isLowercaseMotionKey && keyInput.code === "KeyB") {
      return applyRepeatableCommand(state, {
        ...commandCountPatch(pendingCount),
        kind: "motion_edit",
        motion: "back_word",
        change,
      });
    }

    if (isLowercaseMotionKey && keyInput.key === "0") {
      return applyRepeatableCommand(state, {
        ...commandCountPatch(pendingCount),
        kind: "motion_edit",
        motion: "line_start",
        change,
      });
    }

    if (isModifierFreeKey && keyInput.key === "^") {
      return applyRepeatableCommand(state, {
        ...commandCountPatch(pendingCount),
        kind: "motion_edit",
        motion: "line_indent",
        change,
      });
    }

    if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyG") {
      return applyRepeatableCommand(
        state,
        pendingCount === null
          ? {
              kind: "document_edit",
              change,
              target: "document_end",
            }
          : {
              kind: "document_edit",
              change,
              target: "line_start",
              targetLineNumber: pendingCount,
            },
      );
    }

    if (
      (pendingOperator.kind === "delete" &&
        isLowercaseMotionKey &&
        keyInput.code === "KeyD") ||
      (pendingOperator.kind === "change" &&
        isLowercaseMotionKey &&
        keyInput.code === "KeyC")
    ) {
      return applyRepeatableCommand(state, {
        ...commandCountPatch(pendingCount),
        kind: "line_edit",
        change,
      });
    }

    if (isModifierFreeKey) {
      return handledResult(state, {
        pendingOperator: null,
        pendingMotionPrefix: null,
        pendingCount: null,
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyI") {
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: leftEdge,
      selectionEnd: leftEdge,
      enterInsertMode: true,
    });
  }

  if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyI") {
    const indent = lineIndentCursor(state.value, leftEdge);
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: indent,
      selectionEnd: indent,
      enterInsertMode: true,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyA") {
    const cursor = Math.min(state.value.length, collapsed ? rightEdge + 1 : rightEdge);
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
      enterInsertMode: true,
    });
  }

  if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyA") {
    const cursor = lineEndCursor(state.value, rightEdge);
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
      enterInsertMode: true,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyX") {
    return applyRepeatableCommand(state, {
      ...commandCountPatch(pendingCount),
      kind: "delete_char",
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyD") {
    return handledResult(state, {
      pendingOperator: {
        kind: "delete",
        textObjectPrefix: null,
      },
      pendingMotionPrefix: null,
      pendingCount,
      selectionStart: leftEdge,
      selectionEnd: leftEdge,
    });
  }

  if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyD") {
    return applyRepeatableCommand(state, {
      ...commandCountPatch(pendingCount),
      kind: "motion_edit",
      motion: "line_end",
      change: false,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyC") {
    return handledResult(state, {
      pendingOperator: {
        kind: "change",
        textObjectPrefix: null,
      },
      pendingMotionPrefix: null,
      pendingCount,
      selectionStart: leftEdge,
      selectionEnd: leftEdge,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyG") {
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: "g",
      pendingCount,
      selectionStart: leftEdge,
      selectionEnd: leftEdge,
    });
  }

  if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyG") {
    const targetLineStart =
      pendingCount === null
        ? lineStartForLineNumber(state.value, Number.MAX_SAFE_INTEGER)
        : lineStartForLineNumber(state.value, pendingCount);
    const cursor = lineIndentCursor(state.value, targetLineStart);
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyC") {
    return applyRepeatableCommand(state, {
      ...commandCountPatch(pendingCount),
      kind: "motion_edit",
      motion: "line_end",
      change: true,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyH") {
    const cursor = collapsed
      ? repeatCursorMotion(state.value, leftEdge, pendingCount, (_value, current) =>
          Math.max(0, current - 1),
        )
      : leftEdge;
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyJ") {
    const cursor = repeatCursorMotion(
      state.value,
      rightEdge,
      pendingCount,
      nextLineCursor,
    );
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyK") {
    const cursor = repeatCursorMotion(
      state.value,
      leftEdge,
      pendingCount,
      previousLineCursor,
    );
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyL") {
    const cursor = collapsed
      ? repeatCursorMotion(state.value, rightEdge, pendingCount, (value, current) =>
          Math.min(value.length, current + 1),
        )
      : rightEdge;
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.key === "0") {
    const cursor = lineStartCursor(state.value, leftEdge);
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isModifierFreeKey && keyInput.key === "$") {
    const cursor = lineEndCursor(state.value, rightEdge);
    return handledResult(state, {
      pendingOperator: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isModifierFreeKey && keyInput.key === "^") {
    const cursor = lineIndentCursor(state.value, leftEdge);
    return handledResult(state, {
      pendingOperator: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyW") {
    const cursor = repeatCursorMotion(
      state.value,
      rightEdge,
      pendingCount,
      nextWordCursor,
    );
    return handledResult(state, {
      pendingOperator: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyB") {
    const cursor = repeatCursorMotion(
      state.value,
      leftEdge,
      pendingCount,
      previousWordCursor,
    );
    return handledResult(state, {
      pendingOperator: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyE") {
    const cursor = repeatCursorMotion(
      state.value,
      rightEdge,
      pendingCount,
      wordEndMotionCursor,
    );
    return handledResult(state, {
      pendingOperator: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
    });
  }

  if (isLowercaseMotionKey && keyInput.code === "KeyO") {
    const lineEnd = lineEndCursor(state.value, rightEdge);
    const insertionPoint =
      lineEnd < state.value.length ? lineEnd + 1 : lineEnd;
    const indent = lineIndentText(state.value, rightEdge);
    const nextValue = `${state.value.slice(0, insertionPoint)}${indent}\n${state.value.slice(
      insertionPoint,
    )}`;
    const cursor = insertionPoint + indent.length;
    return handledResult(state, {
      value: nextValue,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
      enterInsertMode: true,
    });
  }

  if (isModifierFreeKey && keyInput.shiftKey && keyInput.code === "KeyO") {
    const insertionPoint = lineStartCursor(state.value, leftEdge);
    const indent = lineIndentText(state.value, leftEdge);
    const nextValue = `${state.value.slice(0, insertionPoint)}${indent}\n${state.value.slice(
      insertionPoint,
    )}`;
    const cursor = insertionPoint + indent.length;
    return handledResult(state, {
      value: nextValue,
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: cursor,
      selectionEnd: cursor,
      enterInsertMode: true,
    });
  }

  if (isModifierFreeKey && keyInput.key === ".") {
    if (!state.lastCommand) {
      return handledResult(state, {
        pendingOperator: null,
        pendingMotionPrefix: null,
        pendingCount: null,
        selectionStart: leftEdge,
        selectionEnd: leftEdge,
      });
    }
    return applyRepeatableCommand(state, state.lastCommand);
  }

  if (isModifierFreeKey) {
    return handledResult(state, {
      pendingOperator: null,
      pendingMotionPrefix: null,
      pendingCount: null,
      selectionStart: leftEdge,
      selectionEnd: leftEdge,
    });
  }

  return unhandledResult(state);
}
