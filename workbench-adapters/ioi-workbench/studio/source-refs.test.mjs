import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { test } from "node:test";

const require = createRequire(import.meta.url);
const {
  collectStudioSourceRefsFromPartialJsonText,
  studioFirstSourceExcerptFromEvent,
  studioJsonObjectFromText,
  studioJsonValueFromText,
  studioRecordValue,
  studioSourceRefFromRecord,
  studioSourceRefsFromRuntimeEvent,
  studioSourceRefsFromRuntimeEvents,
  studioUnescapeJsonStringFragment,
} = require("./source-refs.js");

test("source refs parse valid JSON objects and reject non-object values", () => {
  assert.deepEqual(studioJsonObjectFromText('{"ok":true}'), { ok: true });
  assert.deepEqual(studioJsonObjectFromText('[{"ok":true}]'), {});
  assert.equal(studioJsonValueFromText('[{"ok":true}]')[0].ok, true);
  assert.deepEqual(studioJsonObjectFromText("plain text"), {});
  assert.deepEqual(studioRecordValue(["not", "record"]), {});
});

test("source refs normalize records into public chips", () => {
  assert.deepEqual(studioSourceRefFromRecord({
    source_url: "https://www.example.com/a",
    title: " Example title ",
    snippet: " One\nTwo ",
    status: "used",
  }), {
    title: "Example title",
    url: "https://www.example.com/a",
    domain: "example.com",
    excerpt: "One Two",
    state: "used",
  });
  assert.equal(studioSourceRefFromRecord({ url: "file:///secret" }), null);
});

test("source refs recover partial JSON source text", () => {
  const refs = [];
  collectStudioSourceRefsFromPartialJsonText(
    '{"title":"Quoted \\"source\\"","url":"https://docs.example.test/x","snippet":"Line one\\nline two"}',
    refs,
  );
  assert.equal(refs.length, 1);
  assert.equal(refs[0].title, 'Quoted "source"');
  assert.equal(refs[0].excerpt, "Line one line two");
  assert.equal(studioUnescapeJsonStringFragment('a\\nb'), "a\nb");
});

test("source refs extract unique runtime event citations and excerpts", () => {
  const event = {
    payload: {
      result: {
        sources: [
          { url: "https://example.com/a", title: "A", excerpt: "First excerpt" },
          { url: "https://example.com/a", title: "A", excerpt: "Duplicate excerpt" },
        ],
      },
    },
    data: '{"sources":[{"url":"https://example.com/b","title":"B","snippet":"Second excerpt"}]}',
  };
  const refs = studioSourceRefsFromRuntimeEvent(event);
  assert.equal(refs.length, 2);
  assert.deepEqual(refs.map((ref) => ref.title), ["A", "B"]);
  assert.equal(studioFirstSourceExcerptFromEvent(event), "First excerpt");
  assert.equal(studioSourceRefsFromRuntimeEvents([event, event]).length, 2);
});
