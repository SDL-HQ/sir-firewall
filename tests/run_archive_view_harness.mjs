// Run the archive page's own script against a benchmark index and report what
// it rendered.
//
// The page is a single self-contained HTML file with no module boundary, so its
// script is extracted and evaluated here against a small DOM. Everything the
// page does is its own code: this file supplies only the element stubs and the
// fetch response, and then reads back what the page wrote. Without it the only
// available assertions about this surface are assertions about its text, and
// the defect being fixed, an absent result rendered as a failure, is a
// rendering outcome rather than a string.
//
// Usage: node run_archive_view_harness.mjs <page.html> <index.v3.json|-> [options]
//   --fetch-fails            the index responds 404
//   --filter=<id>=<value>    set a filter and re-apply, repeatable
// Output: one JSON object on stdout.

import { readFileSync } from "node:fs";

const [pagePath, indexPath, ...flags] = process.argv.slice(2);
const fetchFails = flags.includes("--fetch-fails");
const filters = flags
  .filter((flag) => flag.startsWith("--filter="))
  .map((flag) => flag.slice("--filter=".length).split("="));

const html = readFileSync(pagePath, "utf-8");
const open = html.lastIndexOf("<script>");
const close = html.lastIndexOf("</script>");
if (open < 0 || close < 0 || close < open) throw new Error("no script block in the page");
const source = html.slice(open + "<script>".length, close);

const payload = indexPath === "-" ? {} : JSON.parse(readFileSync(indexPath, "utf-8"));

const ELEMENT_IDS = [
  "f-model", "f-pack", "f-proof", "f-kind", "f-status", "f-scope", "f-search",
  "c-runs", "c-nonpass", "c-records", "c-legacy", "c-models", "c-packs", "c-proofs",
  "pair-rows", "recent-rows", "pattern-rows", "pair-summary-line",
  "pair-baseline-definition", "toggle-recent", "toggle-groups", "reset",
];

const elements = new Map();
for (const id of ELEMENT_IDS) {
  elements.set(id, {
    id,
    textContent: "",
    innerHTML: "",
    value: "",
    style: {},
    options: [],
    addEventListener() {},
  });
}

const missing = new Set();
globalThis.document = {
  getElementById(id) {
    if (!elements.has(id)) {
      missing.add(id);
      return null;
    }
    return elements.get(id);
  },
};

globalThis.fetch = async () =>
  fetchFails
    ? { ok: false, status: 404, json: async () => ({}) }
    : { ok: true, status: 200, json: async () => payload };

// The script ends with load(), which is async; await the microtasks it queues.
// apply comes back too, so a filter can be set and the page re-rendered by its
// own code rather than by anything written here.
const run = new Function(`${source}\nreturn { load, apply };`);
const page = run();
await page.load();
await new Promise((resolve) => setTimeout(resolve, 0));

if (filters.length) {
  for (const [id, value] of filters) {
    if (!elements.has(id)) throw new Error(`no such filter: ${id}`);
    elements.get(id).value = value;
  }
  page.apply();
}

const view = {};
for (const [id, element] of elements) {
  view[id] = { textContent: element.textContent, innerHTML: element.innerHTML, value: element.value };
}
process.stdout.write(JSON.stringify({ view, missing_element_ids: [...missing] }, null, 2));
