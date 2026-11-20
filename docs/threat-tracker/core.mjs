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
    && words.every(word => JSON.stringify([r.id,r.title,r.product,r.summary,r.technical,r.exploits,r.controls,r.related]).toLowerCase().includes(word)));
}

export function timelineEvents(record, {kind="all", evidence="all"}={}) {
  const events = [
    ...(record.history||[]).map(e=>({...e,kind:e.kind||"update",reviewStatus:e.reviewStatus||"Source reviewed"})),
    ...(record.live?.timeline||[]).map(e=>({...e,reviewStatus:"Needs review"}))
  ];
  const unique = new Map();
  for(const event of events) {
    if(!event.at || !Number.isFinite(Date.parse(event.at)))continue;
    const key=event.id||[event.at,event.kind,event.title,event.url].join("|");
    if(!unique.has(key)||event.reviewStatus!=="Needs review")unique.set(key,event);
  }
  return [...unique.values()].filter(e=>(kind==="all"||e.kind===kind)
    && (evidence==="all"||(evidence==="reviewed"?e.reviewStatus!=="Needs review":e.reviewStatus==="Needs review")))
    .sort((a,b)=>Date.parse(b.at)-Date.parse(a.at)||a.title.localeCompare(b.title));
}

export function classifyLead(lead,record) {
  const text=[lead.title,lead.description,lead.url].join(" ").toLowerCase();
  const alias=record.title.toLowerCase().match(/^(node2shell|php2shell)/)?.[0];
  const direct=text.includes(record.id.toLowerCase())||Boolean(alias&&text.includes(alias));
  if(/rule|template/i.test(lead.kind))return {type:"rules",label:"Rule candidate",direct:true};
  if(!direct)return {type:"other",label:"Broad repository mention",direct:false};
  if(/patch|backport|secfix/.test(text))return {type:"patches",label:"Patch candidate",direct};
  if(/checker|detect|scanner|fingerprint|hash.lookup/.test(text))return {type:"checkers",label:"Checker candidate",direct};
  return {type:"research",label:/poc|exploit|rce/.test(text)?"Claimed PoC":"Research candidate",direct};
}

export function researchQueue(record) {
  const reviewed=new Set((record.exploits||[]).map(e=>e.repositoryUrl||e.url));
  const leads=(record.live?.leads||[]).filter(e=>e.active!==false&&!reviewed.has(e.url)&&classifyLead(e,record).direct);
  const changedReviews=Object.entries(record.live?.reviewedRepositories||{}).filter(([,v])=>v.headSha!==v.reviewedSha).map(([url,v])=>({url,reviewedSha:v.reviewedSha,headSha:v.headSha}));
  return {leads,questions:record.openQuestions||[],changedReviews,untestedControls:(record.controls||[]).filter(c=>!c.testedAt)};
}

export function evidenceJson(record,snapshot,{scope="full",previousExport=null,now=new Date().toISOString()}={}) {
  const events=timelineEvents(record).filter(e=>scope!=="update"||!previousExport?.at||(e.firstSeen||e.at)>previousExport.at);
  return JSON.stringify({schemaVersion:1,cve:record.id,exportedAt:now,scope,
    baseline:previousExport?.at||null,brief:record,events,collection:{generatedAt:snapshot.generatedAt,health:snapshot.health||[]}},null,2);
}

export function timelineCsv(events) {
  const cell=value=>{
    let text=String(value??"");
    if(/^\s*[=+\-@]|^[\t\r]/.test(text))text="'"+text;
    return '"'+text.replaceAll('"','""')+'"';
  };
  return "\uFEFF"+[["Event date","First seen","Type","Evidence status","Title","Detail","Source","Source field"],
    ...events.map(e=>[e.at,e.firstSeen,e.kind,e.reviewStatus,e.title,e.detail,e.url,e.sourceField])]
    .map(row=>row.map(cell).join(",")).join("\r\n");
}

export function buildReport(record, snapshot, {scope="full", previousExport=null, author="", now=new Date().toISOString()}={}) {
  const update = scope === "update";
  const previousTime = previousExport?.at || null;
  const changes = timelineEvents(record).filter(e => !update || !previousTime || (e.firstSeen||e.at) > previousTime);
  const sections = [];
  const add = (heading, lines) => sections.push({heading, lines:lines?.length ? lines : ["Not established in this snapshot."]});
  if(scope==="brief") {
    add("Summary",[record.summary,`Next action: ${record.nextAction}`,`Severity: ${record.severity}. ${record.severityBasis}. Organisational exposure: not assessed.`]);
    add("Versions and fixes",record.affected.map(v=>`${v.product}: ${v.range}. Fix: ${v.fixed}.`));
    add("Exploit evidence",[record.exploitation.status,record.exploitation.detail,"Source documentation has been reviewed. No independent exploit reproduction is recorded."]);
    add("Controls and gaps",(record.controls||[]).filter(c=>!c.kind.startsWith("Candidate")).slice(0,3).map(c=>`${c.title}: ${c.coverage} Limit: ${c.limitation}`));
    add("Checks still needed",record.openQuestions||[]);
    add("Recent reviewed developments",timelineEvents(record,{evidence:"reviewed"}).slice(0,5).map(e=>`${e.at}: ${e.title}.${e.url?` Source: ${e.url}`:""}`));
    add("Evidence and collection status",[`Brief reviewed ${record.reviewedAt}. Snapshot ${snapshot.generatedAt}.`,record.indicatorAssessment?.summary||"No validated indicators recorded.",`${researchQueue(record).leads.length} active research links require review. Full technical and JSON exports retain additional evidence.`,...(snapshot.health||[]).filter(s=>s.status==="error").map(s=>`${s.name}: ${s.error}. Last success: ${s.lastSuccess||"not recorded"}.`)]);
    add("Primary sources",record.sources.filter(s=>(record.exploitation.sourceIds||[]).includes(s.id)).map(s=>`${s.title}: ${s.url}`));
    return {title:`${record.id} | ${record.title}`,generatedAt:now,author:author.trim().slice(0,100),scope,sections};
  }
  if (update) {
    add("Update summary", [previousTime ? `Previous export: ${previousTime}` : "First export: all available recorded developments are included.", previousExport?.revision === record.revision ? "No material evidence changes since the previous export." : "Review the developments below alongside the current assessment."]);
    add("Recorded developments", [...changes.slice(0,40).map(eventLine),...(changes.length>40?[`${changes.length-40} additional events are available in the evidence JSON and filtered timeline CSV.`]:[])]);
  }
  add("Executive summary", [record.summary, `Severity: ${record.severity}. ${record.severityBasis}`, "Organisational exposure: not assessed."]);
  add("Affected versions and fixes", record.affected.map(x => `${x.product}: ${x.range}. Fix: ${x.fixed}.`));
  add("How exploitation works", [record.technical, ...record.requirements.map(x => `Requirement: ${x}`)]);
  add("Exploitation evidence", [record.exploitation.status, record.exploitation.detail, ...(record.exploitation.sourceIds||[]).map(id => `Evidence source: ${record.sources.find(s=>s.id===id)?.url || "Not established"}`), record.live?.kev?.checkedAt ? `CISA KEV: ${record.live.kev.listed ? "Listed" : "Not listed in the retrieved catalogue"}. Checked ${record.live.kev.checkedAt}. Absence does not establish absence of exploitation.` : "CISA KEV: not checked successfully."]);
  for(const exploit of record.exploits||[])add(`Exploit assessment: ${exploit.title}`,[`Status: ${exploit.reviewStatus}. Reviewed ${exploit.reviewedAt}.`, `Environment: ${exploit.environment}`, `Reported behaviour: ${exploit.behaviour}`, `Requirements: ${exploit.requirements}`, `Limitations: ${exploit.limitations}`, `Source: ${exploit.url}`, ...(exploit.commitSha?[`Reviewed revision: ${exploit.commitSha}`]:[])]);
  add("Mitigations and control coverage", record.mitigations.map(x => `${x.action} Coverage: ${x.coverage} Limit: ${x.limitation}`));
  add("Attack paths and control evidence", (record.controls||[]).map(c=>`${c.title} (${c.kind}). Paths: ${c.paths.join("; ")}. Coverage: ${c.coverage} Limit: ${c.limitation} Validation: ${c.validation} Evidence: ${c.sourceUrls.join("; ")}${c.ruleIds?` Rule identifiers: ${Object.entries(c.ruleIds).map(([k,v])=>`${k}: ${v}`).join("; ")}`:""}${c.query?`\nCandidate ${c.language||"rule"}:\n${c.query}`:""}`));
  add("IOCs", record.iocs.length ? record.iocs.map(x => `${x.value} | ${x.context} | ${x.source}`) : ["No validated CVE-specific IOCs are included. Generic process or error signals do not establish exploitation."]);
  add("Detection and investigation", record.detections.map(x => `${x.title}. Status: ${x.status}. Requirements: ${x.requirements}. Limitations: ${x.limitation}${x.query ? `\n${x.query}` : ""}`));
  add("Related vulnerabilities", record.related.map(x => `${x.id}: ${x.relationship}. Evidence: ${x.source}`));
  add("Indicator assessment", [record.indicatorAssessment?.summary||"No source-backed indicator assessment is recorded.",record.indicatorAssessment?.limitation||"Review source coverage before drawing a conclusion."]);
  add("Outstanding research", [...(record.openQuestions||[]), `${researchQueue(record).leads.length} active research links still need review.`,"Documentation review does not establish that an exploit or control works in another environment."]);
  add("Reviewed repository changes",Object.entries(record.live?.reviewedRepositories||{}).map(([url,v])=>`${url} | Reviewed ${v.reviewedSha} | Latest collected ${v.headSha} | ${v.headSha===v.reviewedSha?"Matches the pinned review":"Code changes need review"} | Checked ${v.checkedAt}`));
  add("Related CVEs awaiting review",(snapshot.candidates||[]).filter(c=>c.relatedTo?.includes(record.id)).map(c=>`${c.id} | ${c.relationship} | ${c.url}`));
  if (!update) add("Recorded developments", timelineEvents(record,{evidence:"reviewed"}).map(eventLine));
  add("Upstream reports awaiting review",[`${(record.live?.timeline||[]).length} dated upstream reports are retained separately. They do not establish exploitation or disclosure dates. Export evidence JSON or the filtered timeline CSV for the complete retained set.`]);
  add("Automatically collected leads", ["The following links are unreviewed leads. Repository mentions and templates are not validated exploits or effective controls.", ...(record.live?.leads||[]).slice(0,20).map(x=>`${x.kind}: ${x.title} | ${x.url} | First seen: ${x.firstSeen||"not recorded"} | ${x.active===false?"Not returned by the latest successful source check":"Returned by a source"}`),...((record.live?.leads||[]).length>20?[`${record.live.leads.length-20} additional retained links are included in the evidence JSON.`]:[])]);
  add("Collection and assessment limits", [`Analyst brief reviewed: ${record.reviewedAt}.`, `Snapshot generated: ${snapshot.generatedAt}.`, `Evidence revision: ${record.revision}.`, "A successful collection does not mean every linked source was reviewed. Untested rules require validation before use.", ...(snapshot.health||[]).map(x => `${x.name}: ${x.status}. Last success: ${x.lastSuccess || "None recorded"}.${x.error ? ` Error: ${x.error}` : ""}`)]);
  add("Sources", [...record.sources.map(s=>`${s.title} | ${s.publisher} | ${s.url}`), ...(record.live?.references||[]).map(x=>`CVE record reference (unreviewed) | ${x}`)]);
  return {title:`${record.id} | ${record.title}`, generatedAt:now, author:author.trim().slice(0,100), scope, sections};
}

function eventLine(e) {return `${e.at} | ${e.kind} | ${e.reviewStatus}: ${e.title}. ${e.detail||""} First seen: ${e.firstSeen||"Not recorded"}.${e.url?` Source: ${e.url}`:""}${e.sourceField?` Source field: ${e.sourceField}`:""}`;}

export function reportHtml(report) {
  const h=escapeHtml;
  return `<!doctype html><html lang="en-GB"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>${h(report.title)}</title><style>body{font:11pt/1.5 Arial,sans-serif;color:#171a16;margin:30px;max-width:900px}h1{font-size:22pt;line-height:1.2}h2{font-size:13pt;margin-top:24px;break-after:avoid}p{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#555}@page{size:A4;margin:18mm}@media print{body{margin:0}.controls{display:none}}button{padding:10px 14px;cursor:pointer}</style></head><body><div class="controls"><button onclick="window.print()">Print / save PDF</button></div><h1>${h(report.title)}</h1><p><small>Generated: ${h(report.generatedAt)}${report.author ? ` | Prepared by: ${h(report.author)}`:""} | ${report.scope === "update" ? "Update report":report.scope === "brief"?"Summary report":"Technical report"}</small></p>${report.sections.map(s=>`<section><h2>${h(s.heading)}</h2>${s.lines.map(l=>`<p>${h(l)}</p>`).join("")}</section>`).join("")}</body></html>`;
}
