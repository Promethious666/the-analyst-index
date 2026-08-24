import { readFile, writeFile } from "node:fs/promises";

const sources = [
  ["meirwah/awesome-incident-response", "master"],
  ["rshipp/awesome-malware-analysis", "main"],
  ["cugu/awesome-forensics", "master"],
  ["hslatman/awesome-threat-intelligence", "main"],
  ["paragonie/awesome-appsec", "master"],
  ["4ndersonLin/awesome-cloud-security", "master"],
  ["enaqx/awesome-pentest", "master"],
];

const catalogue = await readFile(new URL("../app/catalogue.ts", import.meta.url), "utf8");
const existing = new Set([...catalogue.matchAll(/"([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)","[^"\n]*","(?:Offline|Passive|Active)"/g)].map((match) => match[1].toLowerCase()));
const sourceSet = new Set(sources.map(([slug]) => slug.toLowerCase()));
const provenance = new Map();

for (const [source, branch] of sources) {
  const response = await fetch(`https://raw.githubusercontent.com/${source}/${branch}/README.md`, { headers: { "User-Agent": "the-analyst-index-discovery" } });
  if (!response.ok) throw new Error(`Discovery source unavailable: ${source} (${response.status})`);
  const body = await response.text();
  for (const match of body.matchAll(/https?:\/\/(?:www\.)?github\.com\/([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)/gi)) {
    const slug = match[1].replace(/[)#?].*$/, "").replace(/\.(?:git)$/i, "");
    const key = slug.toLowerCase();
    if (existing.has(key) || sourceSet.has(key) || key.includes("awesome")) continue;
    const citedBy = provenance.get(key) || { slug, sources: [] };
    if (!citedBy.sources.includes(source)) citedBy.sources.push(source);
    provenance.set(key, citedBy);
  }
}

const token = process.env.GITHUB_TOKEN;
const discovered = [...provenance.values()].sort((a, b) => b.sources.length - a.sources.length || a.slug.localeCompare(b.slug)).slice(0, 200);
const checked = [];
for (let index = 0; index < discovered.length; index += 10) {
  checked.push(...await Promise.all(discovered.slice(index, index + 10).map(async (candidate) => {
    if (!token) {
      const response = await fetch(`https://github.com/${candidate.slug}`, { headers: { "User-Agent": "the-analyst-index-discovery" } });
      return { ...candidate, exists: response.ok, status: response.status, evidence: "allowlisted-source-and-repository-existence", reviewState: "quarantined" };
    }
    const response = await fetch(`https://api.github.com/repos/${candidate.slug}`, { headers: { Accept: "application/vnd.github+json", Authorization: `Bearer ${token}`, "User-Agent": "the-analyst-index-discovery" } });
    if (!response.ok) return { ...candidate, exists: false, status: response.status, reviewState: "rejected" };
    const data = await response.json();
    const objectivelyEligible = !data.archived && !data.disabled && Boolean(data.license?.spdx_id) && Boolean(data.description);
    return { slug: candidate.slug, sources: candidate.sources, exists: true, archived: data.archived, disabled: data.disabled, license: data.license?.spdx_id || null, description: data.description || null, stars: data.stargazers_count, pushedAt: data.pushed_at, defaultBranch: data.default_branch, evidence: "allowlisted-source-and-github-metadata", reviewState: objectivelyEligible ? "quarantined-eligible" : "quarantined-incomplete" };
  })));
}

const report = {
  schemaVersion: 1,
  generatedAt: new Date().toISOString(),
  policy: "Discovery is not endorsement. Candidates never enter the reviewed catalogue automatically.",
  sources: sources.map(([repository]) => repository),
  existingCatalogueEntries: existing.size,
  discovered: provenance.size,
  checked: checked.length,
  candidates: checked.filter((candidate) => candidate.exists),
  rejected: checked.filter((candidate) => !candidate.exists),
};
await writeFile(new URL("../candidate-discovery.json", import.meta.url), `${JSON.stringify(report, null, 2)}\n`, { flag: "w" });
if (report.rejected.length) console.warn(`${report.rejected.length} candidate links were rejected.`);
console.log(`Discovered ${report.discovered} unique candidates; checked ${report.checked}; ${report.candidates.length} remain quarantined.`);
