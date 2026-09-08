// THE COMMAND PALETTE'S INDEX — surfaces, and what this browser has already read.
//
// A console's search box is the second front door: type a name, land on the thing.
// The rule here is the same as everywhere else on this surface — nothing is fetched
// to answer a keystroke, and nothing is indexed that the daemon did not say. So the
// index is built from two sources only:
//
//   1. the surface registry and the catalogue anchors (static, this branch's own words);
//   2. the KEPT ANSWERS in the read store — the last thing the daemon actually said to
//      this browser about its sources, its jobs, its budgets and the latest sweep of
//      candidates — each carrying the time it was read.
//
// A source, job, venue or budget the browser has not read yet is not in the index,
// and the box says so in its scope line. A palette that searched a fixture would be
// a palette that finds things that are not there.
//
// FRAMEWORK-FREE. The store accessor is injected so the gate can index a fake store.

import { SURFACES, CATALOG_ANCHORS, hashForSurface, hashForCategory, hashForJob } from "./surfaces.mjs";

const KINDS = ["surface", "category", "source", "venue", "job", "budget"];
const KIND_WORD = {
  surface: "surface",
  category: "resources",
  source: "source",
  venue: "venue quoting",
  job: "job record",
  budget: "budget",
};

export const kindWord = (kind) => KIND_WORD[kind] || kind;

const stampOf = (entry) => (entry && entry.at ? String(entry.at).slice(11, 19) + "Z" : null);

// `recall` is read.mjs's recall(key) → { body, at } | null.
export function buildIndex(recall) {
  const items = [];
  for (const s of SURFACES) {
    items.push({ kind: "surface", label: s.label, hint: s.wired ? `#/${s.id}` : `#/${s.id} · designed, not connected`, href: hashForSurface(s.id), key: s.id });
  }
  for (const a of CATALOG_ANCHORS) {
    items.push({ kind: "category", label: a.label, hint: `All resources · ${a.label}`, href: hashForCategory(a.id), key: a.id });
  }

  const sources = recall("sources");
  const srcList = Array.isArray(sources?.body?.sources) ? sources.body.sources : [];
  for (const s of srcList) {
    if (!s || !s.source) continue;
    items.push({
      kind: "source",
      label: s.source,
      hint: `${s.state || "state absent"} · read ${stampOf(sources)}`,
      href: hashForSurface("sources"),
      key: s.source,
      state: s.state || null,
    });
  }

  const cands = recall("candidates");
  const candList = Array.isArray(cands?.body?.candidates) ? cands.body.candidates : [];
  const venues = new Map();
  for (const c of candList) {
    const v = c && c.provider_kind;
    if (!v) continue;
    const cur = venues.get(v) || { n: 0, cheapest: null };
    cur.n += 1;
    const p = c.quote && c.quote.usd_per_hour;
    if (typeof p === "number" && (cur.cheapest === null || p < cur.cheapest)) cur.cheapest = p;
    venues.set(v, cur);
  }
  for (const [v, cur] of venues) {
    items.push({
      kind: "venue",
      label: v,
      hint: `${cur.n} candidate${cur.n === 1 ? "" : "s"} in the latest sweep${cur.cheapest !== null ? ` · from $${cur.cheapest.toFixed(4)}/hr` : ""} · read ${stampOf(cands)}`,
      href: hashForSurface("candidates"),
      key: v,
    });
  }

  const jobs = recall("jobs");
  const jobList = Array.isArray(jobs?.body?.jobs) ? jobs.body.jobs : [];
  for (const j of jobList) {
    const id = j && (j.job_id || j.id);
    if (!id) continue;
    items.push({
      kind: "job",
      label: id,
      hint: `${j.state || "state absent"}${j.placement && j.placement.venue ? ` · ${j.placement.venue}` : ""} · read ${stampOf(jobs)}`,
      href: hashForJob(id),
      key: id,
      state: j.state || null,
    });
  }

  const budgets = recall("budgets");
  const budgetList = Array.isArray(budgets?.body?.budgets) ? budgets.body.budgets : [];
  for (const b of budgetList) {
    if (!b || !(b.name || b.budget_id)) continue;
    items.push({
      kind: "budget",
      label: b.name || b.budget_id,
      hint: `${b.scope || "scope absent"} · ${b.currency || ""} ${b.remaining ?? "—"} remaining · read ${stampOf(budgets)}`,
      href: hashForSurface("spend"),
      key: b.budget_id || b.name,
    });
  }

  return items;
}

// What the index covers, in words, for the scope line under the box. Counts are of
// what is actually indexed, so "0 sources" is a true statement about this browser.
export function indexScope(items) {
  const n = (k) => items.filter((i) => i.kind === k).length;
  const parts = [`${n("surface")} surfaces`];
  const read = [["source", "source"], ["venue", "venue"], ["job", "job"], ["budget", "budget"]]
    .map(([k, w]) => [n(k), w]).filter(([c]) => c > 0).map(([c, w]) => `${c} ${w}${c === 1 ? "" : "s"}`);
  return read.length ? `${parts[0]} · ${read.join(", ")} already read` : `${parts[0]} · nothing read yet to search`;
}

// A filter with a stable order, not a ranking: surfaces first, then the read kinds in
// the order above, and inside a kind by where the match starts (prefix before infix).
// Twelve results at most, and at most four of one kind — "runpod" matched a hundred
// placed jobs and buried the source and the venue under them; a palette that shows
// one kind is a list of that kind. The rest of a kind is counted in the last row's
// hint so the reader knows the ledger holds more.
export function searchIndex(items, query, limit = 12, perKind = 4) {
  const q = String(query || "").trim().toLowerCase();
  if (!q) return items.filter((i) => i.kind === "surface" || i.kind === "category").slice(0, limit);
  const scored = [];
  for (const it of items) {
    const label = it.label.toLowerCase();
    const hint = (it.hint || "").toLowerCase();
    let pos = label.indexOf(q);
    let where = 0;
    if (pos < 0) { pos = hint.indexOf(q); where = 1; }
    if (pos < 0) continue;
    scored.push({ it, rank: [KINDS.indexOf(it.kind), where, pos] });
  }
  scored.sort((a, b) => a.rank[0] - b.rank[0] || a.rank[1] - b.rank[1] || a.rank[2] - b.rank[2] || a.it.label.localeCompare(b.it.label));
  const out = [];
  const seen = new Map();
  for (const { it } of scored) {
    const c = (seen.get(it.kind) || 0) + 1;
    seen.set(it.kind, c);
    if (c > perKind) continue;
    out.push(it);
  }
  for (const [kind, c] of seen) {
    if (c <= perKind) continue;
    const last = [...out].reverse().find((i) => i.kind === kind);
    if (last) out[out.indexOf(last)] = { ...last, hint: `${last.hint} · ${c - perKind} more ${kindWord(kind)}${c - perKind === 1 ? "" : "s"} match` };
  }
  return out.slice(0, limit);
}


