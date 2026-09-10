  // M13 §5 / ACC-15 N2 — KERNEL VOCABULARY STAYS OFF THE CONSUMER PATH, and the renaming happens
  // HERE, in projection, never in the daemon's objects.
  //
  // The reference bundle labels its create action "New Environment". `environment` is the
  // substrate container's kernel name: a consumer opens a session and sees their files, they do
  // not provision an environment. The daemon keeps calling it `environment_ref` — that is the
  // whole point of the rule, and `check:consumer-path-vocabulary`'s negative control fails if the
  // daemon's names ever move to buy a clean scan.
  //
  // This is a RELABEL, not a rewire: the element's href, handlers and data hooks are untouched, so
  // the button still does exactly what it did. Text nodes only — never attributes, never values.
  const CONSUMER_RELABELS = [
    [/\bNew Environment\b/gu, "New Session"],
    [/\bEnvironments\b/gu, "Sessions"],
    [/\bEnvironment\b/gu, "Session"],
  ];

  function relabelTextNode(node) {
    const original = node.nodeValue;
    if (!original || !original.trim()) return;
    let next = original;
    for (const [pattern, replacement] of CONSUMER_RELABELS) next = next.replace(pattern, replacement);
    if (next !== original) node.nodeValue = next;
  }

  function relabelConsumerVocabulary(root) {
    const scope = root && root.nodeType === 1 ? root : document.body;
    if (!scope) return;
    const walker = document.createTreeWalker(scope, NodeFilter.SHOW_TEXT, {
      acceptNode(node) {
        // Skip machine surfaces: script and style bodies are not read by anyone.
        const parent = node.parentNode;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.nodeName;
        if (tag === "SCRIPT" || tag === "STYLE" || tag === "TEXTAREA") return NodeFilter.FILTER_REJECT;
        return NodeFilter.FILTER_ACCEPT;
      },
    });
    const pending = [];
    for (let node = walker.nextNode(); node; node = walker.nextNode()) pending.push(node);
    for (const node of pending) relabelTextNode(node);
  }

  // The SPA re-renders, so a one-shot pass would be undone by the next paint. Observe and re-apply.
  function startConsumerVocabularyProjection() {
    if (!document.body) return;
    relabelConsumerVocabulary(document.body);
    const observer = new MutationObserver((records) => {
      for (const record of records) {
        for (const added of record.addedNodes) {
          if (added.nodeType === 3) relabelTextNode(added);
          else if (added.nodeType === 1) relabelConsumerVocabulary(added);
        }
        if (record.type === "characterData" && record.target?.nodeType === 3) relabelTextNode(record.target);
      }
    });
    observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startConsumerVocabularyProjection);
  } else {
    startConsumerVocabularyProjection();
  }
