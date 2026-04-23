import assert from "node:assert/strict";
import {
  applyChatVimNormalKey,
  type ChatVimKeyInput,
  type ChatVimNormalState,
} from "./chatVimComposer.ts";

function baseState(
  value: string,
  selectionStart: number,
  selectionEnd = selectionStart,
): ChatVimNormalState {
  return {
    value,
    selectionStart,
    selectionEnd,
    pendingOperator: null,
    pendingMotionPrefix: null,
    pendingCount: null,
    lastCommand: null,
  };
}

function keyInput(
  key: string,
  code: string,
  options: Partial<ChatVimKeyInput> = {},
): ChatVimKeyInput {
  return {
    key,
    code,
    shiftKey: false,
    altKey: false,
    ctrlKey: false,
    metaKey: false,
    ...options,
  };
}

{
  const pending = applyChatVimNormalKey(
    baseState("one\ntwo\nthree", 5),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(pending, keyInput("d", "KeyD"));

  assert.equal(applied.value, "one\nthree");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.equal(applied.pendingOperator, null);
  assert.deepEqual(applied.lastCommand, {
    kind: "line_edit",
    change: false,
  });
}

{
  const pending = applyChatVimNormalKey(
    baseState("one\ntwo", 5),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(pending, keyInput("d", "KeyD"));

  assert.equal(applied.value, "one");
  assert.equal(applied.selectionStart, 3);
  assert.equal(applied.selectionEnd, 3);
}

{
  const pending = applyChatVimNormalKey(
    baseState("  keep\nnext", 3),
    keyInput("c", "KeyC"),
  );
  const applied = applyChatVimNormalKey(pending, keyInput("c", "KeyC"));

  assert.equal(applied.value, "  \nnext");
  assert.equal(applied.selectionStart, 2);
  assert.equal(applied.selectionEnd, 2);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "line_edit",
    change: true,
  });
}

{
  const applied = applyChatVimNormalKey(
    baseState("alpha beta\ngamma delta", 6),
    keyInput("D", "KeyD", { shiftKey: true }),
  );

  assert.equal(applied.value, "alpha \ngamma delta");
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "line_end",
    change: false,
  });

  const repeated = applyChatVimNormalKey(
    {
      ...applied,
      selectionStart: 13,
      selectionEnd: 13,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "alpha \ngamma ");
  assert.equal(repeated.selectionStart, 13);
  assert.equal(repeated.selectionEnd, 13);
}

{
  const insertAtIndent = applyChatVimNormalKey(
    baseState("  indented", 6),
    keyInput("I", "KeyI", { shiftKey: true }),
  );
  const appendAtLineEnd = applyChatVimNormalKey(
    baseState("  indented", 2),
    keyInput("A", "KeyA", { shiftKey: true }),
  );

  assert.equal(insertAtIndent.selectionStart, 2);
  assert.equal(insertAtIndent.enterInsertMode, true);
  assert.equal(appendAtLineEnd.selectionStart, "  indented".length);
  assert.equal(appendAtLineEnd.enterInsertMode, true);
}

{
  const movedToIndent = applyChatVimNormalKey(
    baseState("    alpha beta", 10),
    keyInput("^", "Digit6", { shiftKey: true }),
  );

  assert.equal(movedToIndent.selectionStart, 4);
  assert.equal(movedToIndent.selectionEnd, 4);
}

{
  const countedMotion = applyChatVimNormalKey(
    applyChatVimNormalKey(
      baseState("alpha beta gamma delta", 0),
      keyInput("2", "Digit2"),
    ),
    keyInput("w", "KeyW"),
  );

  assert.equal(countedMotion.selectionStart, 11);
  assert.equal(countedMotion.selectionEnd, 11);
}

{
  const movedToSecondLine = applyChatVimNormalKey(
    applyChatVimNormalKey(
      applyChatVimNormalKey(baseState("zero\n  one\ntwo", 11), keyInput("2", "Digit2")),
      keyInput("g", "KeyG"),
    ),
    keyInput("g", "KeyG"),
  );

  assert.equal(movedToSecondLine.selectionStart, 7);
  assert.equal(movedToSecondLine.selectionEnd, 7);
  assert.equal(movedToSecondLine.pendingMotionPrefix, null);
  assert.equal(movedToSecondLine.pendingCount, null);
}

{
  const movedToLastLine = applyChatVimNormalKey(
    baseState("zero\n  one\ntwo", 0),
    keyInput("G", "KeyG", { shiftKey: true }),
  );
  const movedToSecondLine = applyChatVimNormalKey(
    applyChatVimNormalKey(baseState("zero\n  one\ntwo", 0), keyInput("2", "Digit2")),
    keyInput("G", "KeyG", { shiftKey: true }),
  );

  assert.equal(movedToLastLine.selectionStart, 11);
  assert.equal(movedToLastLine.selectionEnd, 11);
  assert.equal(movedToSecondLine.selectionStart, 7);
  assert.equal(movedToSecondLine.selectionEnd, 7);
}

{
  const pendingDelete = applyChatVimNormalKey(
    baseState("one\ntwo\nthree", 8),
    keyInput("d", "KeyD"),
  );
  const pendingDocumentMotion = applyChatVimNormalKey(
    pendingDelete,
    keyInput("g", "KeyG"),
  );
  const applied = applyChatVimNormalKey(
    pendingDocumentMotion,
    keyInput("g", "KeyG"),
  );

  assert.equal(applied.value, "three");
  assert.equal(applied.selectionStart, 0);
  assert.equal(applied.selectionEnd, 0);
  assert.deepEqual(applied.lastCommand, {
    kind: "document_edit",
    change: false,
    target: "line_start",
    targetLineNumber: 1,
  });

  const repeated = applyChatVimNormalKey(
    {
      ...applied,
      value: "alpha\nbeta\ngamma",
      selectionStart: 6,
      selectionEnd: 6,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "beta\ngamma");
}

{
  const pendingChange = applyChatVimNormalKey(
    baseState("one\ntwo\nthree", 8),
    keyInput("c", "KeyC"),
  );
  const pendingDocumentMotion = applyChatVimNormalKey(
    pendingChange,
    keyInput("g", "KeyG"),
  );
  const applied = applyChatVimNormalKey(
    pendingDocumentMotion,
    keyInput("g", "KeyG"),
  );

  assert.equal(applied.value, "three");
  assert.equal(applied.selectionStart, 0);
  assert.equal(applied.selectionEnd, 0);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "document_edit",
    change: true,
    target: "line_start",
    targetLineNumber: 1,
  });
}

{
  const pendingDelete = applyChatVimNormalKey(
    baseState("one\ntwo\nthree", 4),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(
    pendingDelete,
    keyInput("G", "KeyG", { shiftKey: true }),
  );

  assert.equal(applied.value, "one\n");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.deepEqual(applied.lastCommand, {
    kind: "document_edit",
    change: false,
    target: "document_end",
  });

  const repeated = applyChatVimNormalKey(
    {
      ...applied,
      value: "alpha\nbeta\ngamma",
      selectionStart: 6,
      selectionEnd: 6,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "alpha\n");
}

{
  const pendingChange = applyChatVimNormalKey(
    baseState("one\ntwo\nthree", 4),
    keyInput("c", "KeyC"),
  );
  const applied = applyChatVimNormalKey(
    pendingChange,
    keyInput("G", "KeyG", { shiftKey: true }),
  );

  assert.equal(applied.value, "one\n");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "document_edit",
    change: true,
    target: "document_end",
  });
}

{
  const movedDown = applyChatVimNormalKey(
    baseState("alpha\nbeta\ngamma", 2),
    keyInput("j", "KeyJ"),
  );
  const movedUp = applyChatVimNormalKey(
    baseState("alpha\nbeta\ngamma", 8),
    keyInput("k", "KeyK"),
  );

  assert.equal(movedDown.selectionStart, 8);
  assert.equal(movedDown.selectionEnd, 8);
  assert.equal(movedUp.selectionStart, 2);
  assert.equal(movedUp.selectionEnd, 2);
}

{
  const openBelow = applyChatVimNormalKey(
    baseState("  one\nnext", 2),
    keyInput("o", "KeyO"),
  );
  const openAbove = applyChatVimNormalKey(
    baseState("one\n  next", 7),
    keyInput("O", "KeyO", { shiftKey: true }),
  );

  assert.equal(openBelow.value, "  one\n  \nnext");
  assert.equal(openBelow.selectionStart, 8);
  assert.equal(openBelow.selectionEnd, 8);
  assert.equal(openBelow.enterInsertMode, true);

  assert.equal(openAbove.value, "one\n  \n  next");
  assert.equal(openAbove.selectionStart, 6);
  assert.equal(openAbove.selectionEnd, 6);
  assert.equal(openAbove.enterInsertMode, true);
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("    alpha beta", 12),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(
    pendingOperator,
    keyInput("^", "Digit6", { shiftKey: true }),
  );

  assert.equal(applied.value, "    ta");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "line_indent",
    change: false,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("    alpha beta", 9),
    keyInput("c", "KeyC"),
  );
  const applied = applyChatVimNormalKey(
    pendingOperator,
    keyInput("^", "Digit6", { shiftKey: true }),
  );

  assert.equal(applied.value, "     beta");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "line_indent",
    change: true,
  });
}

{
  const countedDelete = applyChatVimNormalKey(
    applyChatVimNormalKey(baseState("alpha beta", 0), keyInput("3", "Digit3")),
    keyInput("x", "KeyX"),
  );

  assert.equal(countedDelete.value, "ha beta");
  assert.deepEqual(countedDelete.lastCommand, {
    count: 3,
    kind: "delete_char",
  });

  const repeated = applyChatVimNormalKey(
    {
      ...countedDelete,
      selectionStart: 0,
      selectionEnd: 0,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "beta");
}

{
  const pendingDelete = applyChatVimNormalKey(
    baseState("    alpha beta", 9),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(
    pendingDelete,
    keyInput("0", "Digit0"),
  );

  assert.equal(applied.value, " beta");
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "line_start",
    change: false,
  });
}

{
  const pendingChange = applyChatVimNormalKey(
    baseState("    alpha beta", 9),
    keyInput("c", "KeyC"),
  );
  const applied = applyChatVimNormalKey(
    pendingChange,
    keyInput("0", "Digit0"),
  );

  assert.equal(applied.value, " beta");
  assert.equal(applied.selectionStart, 0);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "line_start",
    change: true,
  });
}

{
  const countedLineDelete = applyChatVimNormalKey(
    applyChatVimNormalKey(baseState("one\ntwo\nthree\nfour", 0), keyInput("2", "Digit2")),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(countedLineDelete, keyInput("d", "KeyD"));

  assert.equal(applied.value, "three\nfour");
  assert.deepEqual(applied.lastCommand, {
    count: 2,
    kind: "line_edit",
    change: false,
  });
}

{
  const pendingDelete = applyChatVimNormalKey(
    applyChatVimNormalKey(
      baseState("alpha beta gamma delta", 0),
      keyInput("2", "Digit2"),
    ),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(pendingDelete, keyInput("w", "KeyW"));

  assert.equal(applied.value, "gamma delta");
  assert.deepEqual(applied.lastCommand, {
    count: 2,
    kind: "motion_edit",
    motion: "word",
    change: false,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("alpha beta gamma", 7),
    keyInput("c", "KeyC"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("i", "KeyI"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput("w", "KeyW"),
  );

  assert.equal(applied.value, "alpha  gamma");
  assert.equal(applied.selectionStart, 6);
  assert.equal(applied.selectionEnd, 6);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "inner_word",
    change: true,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("alpha beta gamma", 6),
    keyInput("d", "KeyD"),
  );
  const applied = applyChatVimNormalKey(
    pendingOperator,
    keyInput("b", "KeyB"),
  );

  assert.equal(applied.value, "beta gamma");
  assert.equal(applied.selectionStart, 0);
  assert.equal(applied.selectionEnd, 0);
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "back_word",
    change: false,
  });

  const repeated = applyChatVimNormalKey(
    {
      ...applied,
      selectionStart: 5,
      selectionEnd: 5,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "gamma");
  assert.equal(repeated.selectionStart, 0);
  assert.equal(repeated.selectionEnd, 0);
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("alpha beta gamma", 6),
    keyInput("c", "KeyC"),
  );
  const applied = applyChatVimNormalKey(
    pendingOperator,
    keyInput("b", "KeyB"),
  );

  assert.equal(applied.value, "beta gamma");
  assert.equal(applied.selectionStart, 0);
  assert.equal(applied.selectionEnd, 0);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "motion_edit",
    motion: "back_word",
    change: true,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("alpha beta gamma delta", 7),
    keyInput("d", "KeyD"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("a", "KeyA"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput("w", "KeyW"),
  );

  assert.equal(applied.value, "alpha gamma delta");
  assert.equal(applied.selectionStart, 6);
  assert.equal(applied.selectionEnd, 6);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "around_word",
    change: false,
  });

  const repeated = applyChatVimNormalKey(
    {
      ...applied,
      selectionStart: 6,
      selectionEnd: 6,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "alpha delta");
  assert.equal(repeated.selectionStart, 6);
  assert.equal(repeated.selectionEnd, 6);
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState('say "hello world" now', 8),
    keyInput("c", "KeyC"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("i", "KeyI"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput('"', "Quote", { shiftKey: true }),
  );

  assert.equal(applied.value, 'say "" now');
  assert.equal(applied.selectionStart, 5);
  assert.equal(applied.selectionEnd, 5);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "inner_double_quote",
    change: true,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState('say "hello" and "bye"', 6),
    keyInput("d", "KeyD"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("a", "KeyA"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput('"', "Quote", { shiftKey: true }),
  );

  assert.equal(applied.value, "say  and \"bye\"");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "around_double_quote",
    change: false,
  });

  const repeated = applyChatVimNormalKey(
    {
      ...applied,
      selectionStart: 10,
      selectionEnd: 10,
    },
    keyInput(".", "Period"),
  );

  assert.equal(repeated.value, "say  and ");
  assert.equal(repeated.selectionStart, 9);
  assert.equal(repeated.selectionEnd, 9);
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("say 'hello world' now", 8),
    keyInput("c", "KeyC"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("i", "KeyI"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput("'", "Quote"),
  );

  assert.equal(applied.value, "say '' now");
  assert.equal(applied.selectionStart, 5);
  assert.equal(applied.selectionEnd, 5);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "inner_single_quote",
    change: true,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("sum(foo, bar) + baz", 6),
    keyInput("c", "KeyC"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("i", "KeyI"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput("(", "Digit9", { shiftKey: true }),
  );

  assert.equal(applied.value, "sum() + baz");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "inner_paren",
    change: true,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("list[alpha, beta] + gamma", 7),
    keyInput("d", "KeyD"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("a", "KeyA"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput("[", "BracketLeft"),
  );

  assert.equal(applied.value, "list + gamma");
  assert.equal(applied.selectionStart, 4);
  assert.equal(applied.selectionEnd, 4);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "around_bracket",
    change: false,
  });
}

{
  const pendingOperator = applyChatVimNormalKey(
    baseState("value { nested { brace } set } done", 16),
    keyInput("c", "KeyC"),
  );
  const pendingTextObject = applyChatVimNormalKey(
    pendingOperator,
    keyInput("i", "KeyI"),
  );
  const applied = applyChatVimNormalKey(
    pendingTextObject,
    keyInput("{", "BracketLeft", { shiftKey: true }),
  );

  assert.equal(applied.value, "value { nested {} set } done");
  assert.equal(applied.selectionStart, applied.selectionEnd);
  assert.equal(applied.enterInsertMode, true);
  assert.deepEqual(applied.lastCommand, {
    kind: "text_object_edit",
    textObject: "inner_brace",
    change: true,
  });
}
