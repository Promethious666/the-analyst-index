import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../", import.meta.url);
const read = (path) => readFile(new URL(path, root), "utf8");

test("ships a coherent evidence-led first catalogue", async () => {
  const [source, catalogue] = await Promise.all([read("app/tool-directory.tsx"), read("app/catalogue.ts")]);
  const cards = [...catalogue.matchAll(/^\s*\["/gm)];
  assert.ok(cards.length >= 100, `expected at least 100 tools, found ${cards.length}`);
  for (const field of ["interaction", "data", "setup", "delivery", "limitation", "reviewed"]) {
    assert.ok(catalogue.includes(field), `missing decision field: ${field}`);
  }
  for (const query of ["Windows event logs", "Suspicious file", "Packet capture", "Threat intelligence"]) {
    assert.ok(source.includes(query), `missing example path: ${query}`);
  }
});

test("provides comparison, details, guided workflows and a local watchlist", async () => {
  const source = await read("app/tool-directory.tsx");
  for (const capability of ["workflowMap", "Comparison", "Detail", "analyst-index-watchlist", "Know before use"]) {
    assert.ok(source.includes(capability), `missing capability: ${capability}`);
  }
});

test("automated discovery is allowlisted, evidence-led and quarantined", async () => {
  const source = await read("scripts/discover-candidates.mjs");
  assert.match(source, /const sources = \[/);
  assert.match(source, /reviewState: "quarantined"/);
  assert.match(source, /never enter the reviewed catalogue automatically/i);
  assert.match(source, /writeFile\(new URL\("\.\.\/candidate-discovery\.json"/);
  assert.doesNotMatch(source, /writeFile\(new URL\("\.\.\/app\/catalogue\.ts"/);
});

test("search is local and external repository links are isolated", async () => {
  const source = await read("app/tool-directory.tsx");
  assert.match(source, /useMemo/);
  assert.match(source, /target="_blank" rel="noreferrer"/);
  assert.doesNotMatch(source, /fetch\s*\(|XMLHttpRequest|innerHTML|dangerouslySetInnerHTML|eval\s*\(/);
  assert.match(source, /NO QUERY LOGGING/);
});

test("uses no remote fonts, scripts, analytics or tracking", async () => {
  const [layout, css, page] = await Promise.all([
    read("app/layout.tsx"), read("app/globals.css"), read("app/page.tsx"),
  ]);
  const joined = `${layout}\n${css}\n${page}`;
  assert.doesNotMatch(joined, /next\/font|googleapis|gtag|analytics|segment|hotjar/i);
  assert.match(layout, /The Analyst Index/);
  assert.match(page, /ToolDirectory/);
});

test("includes accessibility and reduced-motion safeguards", async () => {
  const [source, css] = await Promise.all([
    read("app/tool-directory.tsx"), read("app/globals.css"),
  ]);
  assert.match(source, /aria-label="Primary navigation"/);
  assert.match(source, /label htmlFor="tool-search"/);
  assert.match(css, /:focus-visible/);
  assert.match(css, /prefers-reduced-motion/);
});

test("ships the essential personal-project release documents", async () => {
  const [readme, method, security, contributing, licence, workflow] = await Promise.all([
    read("README.md"), read("METHODOLOGY.md"), read("SECURITY.md"), read("CONTRIBUTING.md"), read("LICENSE"), read(".github/workflows/catalogue-health.yml"),
  ]);
  assert.match(readme, /navigation aid, not an endorsement/i);
  assert.match(method, /Discovery is not endorsement/i);
  assert.match(security, /private vulnerability reporting/i);
  assert.match(contributing, /meaningful limitation/i);
  assert.match(licence, /MIT License/);
  assert.match(workflow, /permissions:\s+contents: read/s);
  assert.doesNotMatch(workflow, /uses: actions\/[\w-]+@v\d/);
});
