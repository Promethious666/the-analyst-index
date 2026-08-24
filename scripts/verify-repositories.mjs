import { readFile, writeFile } from "node:fs/promises";

const source = await readFile(new URL("../app/catalogue.ts", import.meta.url), "utf8");
const catalogueRepositories = [...source.matchAll(/"([A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+)","[^"\n]*","(?:Offline|Passive|Active)"/g)].map((match) => match[1]);
if (catalogueRepositories.length < 100) throw new Error(`Catalogue extraction failed (${catalogueRepositories.length} rows).`);
const repositories = [...new Set(catalogueRepositories)];

const check = async (slug) => {
  const token = process.env.GITHUB_TOKEN;
  const response = await fetch(token ? `https://api.github.com/repos/${slug}` : `https://github.com/${slug}`, {
    headers: { Accept: token ? "application/vnd.github+json" : "text/html", "User-Agent": "the-analyst-index-health-check", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  if (!response.ok) {
    return { slug, ok: false, status: response.status };
  }
  if (!token) return { slug, ok: true, metadata: "not requested without a token" };
  const data = await response.json();
  return { slug, ok: true, archived: Boolean(data.archived), defaultBranch: data.default_branch, pushedAt: data.pushed_at, license: data.license?.spdx_id || null };
};

const results = [];
for (let index = 0; index < repositories.length; index += 10) {
  results.push(...await Promise.all(repositories.slice(index, index + 10).map(check)));
}

const report = { checkedAt: new Date().toISOString(), catalogueEntries: catalogueRepositories.length, uniqueRepositories: results.length, failures: results.filter((item) => !item.ok), archived: results.filter((item) => item.archived), repositories: results };
await writeFile(new URL("../repository-health.json", import.meta.url), `${JSON.stringify(report, null, 2)}\n`, { flag: "w" });
if (report.failures.length) throw new Error(`${report.failures.length} repository checks failed; last-known-good catalogue preserved.`);
console.log(`Verified ${report.uniqueRepositories} repositories for ${report.catalogueEntries} entries; ${report.archived.length} archived.`);
