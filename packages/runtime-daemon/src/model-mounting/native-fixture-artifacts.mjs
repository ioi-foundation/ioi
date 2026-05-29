export function nativeFixtureStaticWebsiteJson(inputStr) {
  const lower = String(inputStr || "").toLowerCase();
  if (
    !lower.includes("agent-studio-conversation-artifact-generator") &&
    !lower.includes("you create polished, self-contained static website artifacts")
  ) {
    return null;
  }
  if (!lower.includes("return only a json object") || !lower.includes("html, css, js")) {
    return null;
  }

  const topic = nativeFixtureWebsiteTopic(inputStr);
  const title = titleCaseText(topic);
  const slug = topic.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "generated-site";
  return JSON.stringify({
    title,
    summary: `A model-shaped static website artifact for ${topic}.`,
    html: `
<main class="site" data-topic="${slug}">
  <section class="hero">
    <p class="eyebrow">Field guide</p>
    <h1>${title}</h1>
    <p class="lead">A clear, human-readable guide to ${topic}: what it is, why it matters, and what to watch next.</p>
  </section>
  <section class="content-strip" aria-label="Key ideas">
    <article>
      <span>01</span>
      <h2>What changes</h2>
      <p>${titleCaseText(topic)} matters when old assumptions stop being enough. The page frames the shift in practical terms instead of hiding it behind jargon.</p>
    </article>
    <article>
      <span>02</span>
      <h2>Why people care</h2>
      <p>The story connects the technology to decisions teams can make now: inventory dependencies, choose safer defaults, and communicate risk plainly.</p>
    </article>
    <article>
      <span>03</span>
      <h2>Next step</h2>
      <p>Use the checklist to separate urgent preparation from hype, then revise this artifact with more domain-specific examples.</p>
    </article>
  </section>
</main>`,
    css: `
:root{color-scheme:light;--ink:#10211f;--muted:#51615f;--paper:#f7f3ea;--accent:#0f766e;--panel:#fffdf7;--line:#d7ddd3}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,sans-serif}
.site{min-height:100vh;padding:44px clamp(22px,6vw,76px)}
.hero{max-width:860px;padding:38px 0 44px}
.eyebrow{margin:0 0 16px;color:var(--accent);font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:.14em}
h1{max-width:820px;margin:0;font-size:clamp(42px,8vw,88px);line-height:.94;letter-spacing:0}
.lead{max-width:720px;margin:24px 0 0;color:var(--muted);font-size:clamp(18px,2.4vw,25px);line-height:1.45}
.content-strip{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1px;margin-top:16px;border:1px solid var(--line);background:var(--line);max-width:1040px}
article{background:var(--panel);padding:28px;min-height:240px}article span{color:var(--accent);font-weight:800}h2{margin:36px 0 12px;font-size:24px}article p{margin:0;color:var(--muted);font-size:16px;line-height:1.65}
@media(max-width:820px){.content-strip{grid-template-columns:1fr}.site{padding:30px 20px}article{min-height:auto}}`,
    js: `document.documentElement.dataset.artifactReady = "true";`,
  });
}

function nativeFixtureWebsiteTopic(inputStr) {
  const requestMatch = String(inputStr || "").match(/(?:^|\n)User request:\n([\s\S]*?)$/i);
  const request = String(requestMatch?.[1] || extractedUserQuery(inputStr) || "").trim();
  const topicMatch = request.match(/\b(?:explains?|about|for|on)\s+([^.!?\n]{3,90})/i);
  const topic = String(topicMatch?.[1] || request || "the requested topic")
    .replace(/\b(?:as|with|using)\b.*$/i, "")
    .replace(/^["'`]+|["'`]+$/g, "")
    .trim();
  return topic || "the requested topic";
}

function extractedUserQuery(inputStr) {
  const rawText = String(inputStr);
  const promptText = rawText.includes("\\n") || rawText.includes('\\"')
    ? rawText.replace(/\\n/g, "\n").replace(/\\"/g, '"')
    : rawText;
  const explicit = promptText.match(/(?:^|\n)\s*(?:user|prompt|request)\s*:\s*([\s\S]+)$/i);
  return String(explicit?.[1] || promptText).trim();
}

function titleCaseText(value = "") {
  return String(value || "")
    .replace(/[-_]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}
