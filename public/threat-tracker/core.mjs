export function escapeHtml(value = "") {
  return String(value).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"})[c]);
}

export function safeUrl(value) {
  try { const u = new URL(value); return u.protocol === "https:" && !u.username && !u.password ? u.href : ""; } catch { return ""; }
}

export function filterRecords(records, {query="", product="", scope="all", followed=[], seen={}} = {}) {
  const words = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return records.filter(r => (!product || r.product === product)
    && (scope !== "followed" || followed.includes(r.id))
    && (scope !== "changed" || Boolean(seen[r.id] && seen[r.id] !== r.revision))
    && words.every(word => JSON.stringify([r.id,r.title,r.product,r.summary,r.technical]).toLowerCase().includes(word)));
}

export function buildReport(record, snapshot, {scope="full", previousExport=null, author="", now=new Date().toISOString()}={}) {
  const update = scope === "update";
  const previousTime = previousExport?.at || null;
  const changes = (record.history || []).filter(e => !update || !previousTime || e.at > previousTime);
  const sections = [];
  const add = (heading, lines) => sections.push({heading, lines:lines?.length ? lines : ["Not established in this snapshot."]});
  if (update) {
    add("Update summary", [previousTime ? `Previous export: ${previousTime}` : "First export: all available recorded developments are included.", previousExport?.revision === record.revision ? "No material evidence changes since the previous export." : "Review the developments below alongside the current assessment."]);
    add("Recorded developments", changes.map(e => `${e.at} | ${e.title}. ${e.detail || ""}`));
  }
  add("Executive summary", [record.summary, `Severity: ${record.severity}. ${record.severityBasis}`, "Organisational exposure: not assessed."]);
  add("Affected versions and fixes", record.affected.map(x => `${x.product}: ${x.range}. Fix: ${x.fixed}.`));
  add("How exploitation works", [record.technical, ...record.requirements.map(x => `Requirement: ${x}`)]);
  add("Exploitation evidence", [record.exploitation.status, record.exploitation.detail, ...(record.exploitation.sourceIds||[]).map(id => `Evidence source: ${record.sources.find(s=>s.id===id)?.url || "Not established"}`), record.live?.kev?.checkedAt ? `CISA KEV: ${record.live.kev.listed ? "Listed" : "Not listed in the retrieved catalogue"}. Checked ${record.live.kev.checkedAt}. Absence does not establish absence of exploitation.` : "CISA KEV: not checked successfully."]);
  add("Mitigations and control coverage", record.mitigations.map(x => `${x.action} Coverage: ${x.coverage} Limit: ${x.limitation}`));
  add("IOCs", record.iocs.length ? record.iocs.map(x => `${x.value} | ${x.context} | ${x.source}`) : ["No validated CVE-specific IOCs are included. Generic process or error signals do not establish exploitation."]);
  add("Detection and investigation", record.detections.map(x => `${x.title}. Status: ${x.status}. Requirements: ${x.requirements}. Limitations: ${x.limitation}${x.query ? `\n${x.query}` : ""}`));
  add("Related vulnerabilities", record.related.map(x => `${x.id}: ${x.relationship}. Evidence: ${x.source}`));
  if (!update) add("Recorded developments", (record.history||[]).map(e => `${e.at} | ${e.title}. ${e.detail||""}`));
  add("Automatically collected leads", ["The following links are unreviewed leads. Repository mentions and templates are not validated exploits or effective controls.", ...(record.live?.leads||[]).map(x=>`${x.kind}: ${x.title} | ${x.url}`)]);
  add("Collection and assessment limits", [`Analyst brief reviewed: ${record.reviewedAt}.`, `Snapshot generated: ${snapshot.generatedAt}.`, `Evidence revision: ${record.revision}.`, "A successful collection does not mean every linked source was reviewed. Untested rules require validation before use.", ...(snapshot.health||[]).map(x => `${x.name}: ${x.status}. Last success: ${x.lastSuccess || "None recorded"}.${x.error ? ` Error: ${x.error}` : ""}`)]);
  add("Sources", [...record.sources.map(s=>`${s.title} | ${s.publisher} | ${s.url}`), ...(record.live?.references||[]).map(x=>`CVE record reference (unreviewed) | ${x}`)]);
  return {title:`${record.id} | ${record.title}`, generatedAt:now, author:author.trim().slice(0,100), scope, sections};
}

export function reportHtml(report) {
  const h=escapeHtml;
  return `<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>${h(report.title)}</title><style>body{font:11pt/1.5 Arial,sans-serif;color:#171a16;margin:30px;max-width:900px}h1{font-size:22pt;line-height:1.2}h2{font-size:13pt;margin-top:24px;break-after:avoid}p{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#555}@page{size:A4;margin:18mm}@media print{body{margin:0}.controls{display:none}}button{padding:10px 14px;cursor:pointer}</style></head><body><div class="controls"><button onclick="window.print()">Print / save PDF</button></div><h1>${h(report.title)}</h1><p><small>Generated: ${h(report.generatedAt)}${report.author ? ` | Prepared by: ${h(report.author)}`:""} | ${report.scope === "update" ? "Update report":"Technical report"}</small></p>${report.sections.map(s=>`<section><h2>${h(s.heading)}</h2>${s.lines.map(l=>`<p>${h(l)}</p>`).join("")}</section>`).join("")}</body></html>`;
}
