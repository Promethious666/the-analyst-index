import {escapeHtml as h,safeUrl,filterRecords,buildReport,reportHtml,researchQueue,timelineEvents,timelineCsv,evidenceJson} from "./core.mjs";
import {createDocx} from "./word.mjs";
import {renderExploits,renderControls,renderTimeline,renderResearchGaps} from "./evidence-view.mjs";

const $=selector=>document.querySelector(selector);
const storageKey="threat-tracker-preferences-v1";
const views=[["overview","Overview"],["exploits","Exploits"],["controls","Controls"],["timeline","Timeline"],["technical","Checks"],["sources","Sources"]];
let saved={followed:[],seen:{},exports:{}};
try {
  const value=JSON.parse(localStorage.getItem(storageKey)||"null");
  if(value&&Array.isArray(value.followed)&&value.seen&&typeof value.seen==="object"&&value.exports&&typeof value.exports==="object")saved=value;
} catch { /* Preferences are optional. */ }
const seenOnArrival={...saved.seen};
let snapshot=null,selected=null,activeView="overview",noticeTimer;
let leadFilters={query:"",kind:"all",page:0,older:false},eventFilters={kind:"all",evidence:"reviewed"};
let snapshotTag="",refreshing=false,lastUpdateCheck=0;

function date(value) {
  if(!value||Number.isNaN(Date.parse(value)))return "Not recorded";
  return new Intl.DateTimeFormat("en-GB",{dateStyle:"medium",...(value.length>10?{timeStyle:"short"}:{}),timeZone:"Europe/London"}).format(new Date(value))+(value.length>10?" UK":"");
}
function link(url,title) {
  const valid=safeUrl(url);
  return valid?`<a href="${h(valid)}" target="_blank" rel="noopener noreferrer">${h(title)}</a>`:h(title);
}
function notice(message) {
  $("#notice").textContent=message; $("#notice").hidden=false;
  clearTimeout(noticeTimer); noticeTimer=setTimeout(()=>$("#notice").hidden=true,5000);
}
function persist() {
  try { localStorage.setItem(storageKey,JSON.stringify(saved)); }
  catch { notice("Browser storage is unavailable. These preferences will last for this visit only."); }
}
const list=items=>`<ul>${items.map(x=>`<li>${h(x)}</li>`).join("")}</ul>`;
const section=(title,content)=>`<section class="brief-section"><h3>${h(title)}</h3>${content}</section>`;
const fold=(title,content)=>`<details class="technical-item"><summary>${h(title)}</summary>${content}</details>`;
const changed=r=>Boolean(seenOnArrival[r.id]&&seenOnArrival[r.id]!==r.revision);
function currentFilters() {
  return {query:$("#search").value,product:$("#product").value,scope:$("#scope").value,followed:saved.followed,seen:seenOnArrival};
}
function resetFilters() {
  $("#search").value=""; $("#scope").value="all"; $("#product").value="";
}
function renderStats() {
  const values=[
    [snapshot.records.length,"Tracked vulnerabilities"],
    [snapshot.records.filter(r=>r.fixStatus==="Available").length,"Fix available"],
    [snapshot.records.filter(r=>saved.followed.includes(r.id)).length,"Following"],
    [snapshot.records.reduce((n,r)=>n+researchQueue(r).leads.length,0),"Research links to review"]
  ];
  $("#stats").innerHTML=values.map(([count,label])=>`<div class="stat"><strong>${count}</strong><span>${h(label)}</span></div>`).join("");
}
function renderList(found) {
  $("#result-count").textContent=String(found.length);
  $("#records").innerHTML=found.length?found.map(r=>`<button class="record ${r.id===selected?"selected":""}" data-select="${h(r.id)}" ${r.id===selected?'aria-current="true"':""}><span class="cve">${h(r.id)}</span><span class="record-name">${h(r.title)}</span><span class="record-product">${h(r.product)}${saved.followed.includes(r.id)?" / Following":""}</span><span class="record-bottom"><span class="tag ${h(r.severity.toLowerCase())}">${h(r.severity)}</span><span class="tag ${r.fixStatus==="Available"?"available":"pending"}">${r.fixStatus==="Available"?"Fix available":"Fix pending"}</span>${changed(r)?'<span class="tag changed">Updated</span>':""}</span></button>`).join(""):'<p class="empty">No matches. Change the filters or select Reset.</p>';
}
function renderWorkspace() {
  const found=filterRecords(snapshot.records,currentFilters());
  if(!found.some(r=>r.id===selected)) { selected=found[0]?.id||null; activeView="overview"; }
  if(selected)history.replaceState(null,"",`#${encodeURIComponent(selected)}`);
  renderStats(); renderList(found); renderBrief();
}
function select(id) {
  if(!snapshot.records.some(r=>r.id===id))return;
  if(!filterRecords(snapshot.records,currentFilters()).some(r=>r.id===id))resetFilters();
  selected=id; activeView="overview"; leadFilters={query:"",kind:"all",page:0,older:false};eventFilters={kind:"all",evidence:"reviewed"};renderWorkspace();
}
function renderBrief() {
  const r=snapshot.records.find(r=>r.id===selected);
  if(!r) { $("#brief").innerHTML='<p class="empty">Select a matching vulnerability to see its details.</p>'; return; }
  saved.seen[r.id]=r.revision; persist();
  const live=r.live||{},follows=saved.followed.includes(r.id);
  const sources=r.sources.map(s=>`<div class="source">${link(s.url,s.title)}<span class="meta">${h(s.publisher)} / ${h(s.type)} / Reviewed ${h(s.reviewedAt)}</span></div>`).join("");
  const versions=`<dl class="facts">${r.affected.map(a=>`<div class="fact"><dt>${h(a.product)}</dt><dd>${h(a.range)}<br><strong>Fixed version: ${h(a.fixed)}</strong></dd></div>`).join("")}</dl>`;
  const mitigations=r.mitigations.map(m=>`<div class="mitigation"><strong>${h(m.action)}</strong><p>${h(m.coverage)}</p><p><strong>Limit:</strong> ${h(m.limitation)}</p></div>`).join("");
  const kevStatus=live.kev?.checkedAt?(live.kev.listed?"Listed by CISA":"Not listed by CISA"):"Not checked yet";
  const kevNote=live.kev?.checkedAt?`<p>CISA's known-exploited catalogue: ${live.kev.listed?"listed":"not listed"}, checked ${h(date(live.kev.checkedAt))}. An unlisted CVE can still be exploited.</p>`:"";
  const risk=live.epss?`<p>EPSS estimates a ${(Number(live.epss.score)*100).toFixed(2)}% chance of exploitation over the next 30 days. Score dated ${h(live.epss.date)}. This is a prediction.</p>`:"";
  const overview=`<p>${h(r.summary)}</p><div class="next-action"><strong>What to do next</strong><p>${h(r.nextAction)}</p></div>${renderResearchGaps(r)}${section("Versions and fixes",versions)}${section("Attack information",`<p>${h(r.exploitation.detail)}</p>${kevNote}${risk}`)}${section("Fixes and workarounds",mitigations)}`;
  const checks=r.detections.map((d,i)=>`<section class="brief-section"><h3>${h(d.title)}</h3><span class="tag neutral">${h(d.status)}</span><p><strong>Needs:</strong> ${h(d.requirements)}<br><strong>Limit:</strong> ${h(d.limitation)}</p>${d.query?`<pre class="code-block"><code>${h(d.query)}</code></pre><button class="quiet-button" data-copy-query="${i}">Copy query</button>`:""}</section>`).join("");
  const related=r.related.length?r.related.map(x=>`<div class="source"><strong>${h(x.id)}</strong><p>${h(x.relationship)}</p>${link(x.source,"Read source")}${snapshot.records.some(t=>t.id===x.id)?` / <button class="text-button" data-select="${h(x.id)}">Open vulnerability</button>`:""}</div>`).join(""):"<p>No confirmed connections recorded.</p>";
  const references=(live.references||[]).map(url=>`<div class="source">${link(url,url)}<span class="meta">CVE record reference / Needs checking</span></div>`).join("");
  const technical=fold("How the attack works",`<p>${h(r.technical)}</p>${list(r.requirements)}`)
    +fold("Checks and queries",checks)
    +fold("IOCs",`<p>${h(r.indicatorAssessment?.summary||"No confirmed CVE-specific indicators are recorded.")}</p><p class="small">${h(r.indicatorAssessment?.limitation||"A crash or generic process event does not prove exploitation.")}</p>${r.iocs.length?list(r.iocs.map(i=>`${i.value}: ${i.context}. Source: ${i.source}`)):""}`)
    +fold("Related vulnerabilities",related);
  const sourceView=sources+(references?`<details class="technical-item"><summary>Other references (${(live.references||[]).length})</summary>${references}</details>`:"")+`<p class="small">Technical notes reviewed: ${h(date(r.reviewedAt))}. Automatic update: ${h(date(snapshot.generatedAt))}.</p>`;
  const panels={overview,exploits:renderExploits(r,leadFilters),controls:renderControls(r),timeline:renderTimeline(r,eventFilters),technical,sources:sourceView};
  $("#brief").innerHTML=`<header class="brief-header"><div class="brief-title-row"><div><p class="brief-id">${h(r.id)} / ${h(r.product)}</p><h2>${h(r.title)}</h2><p class="review-date">Reviewed ${h(date(r.reviewedAt))}</p></div><div class="header-actions"><button id="follow" class="quiet-button" aria-pressed="${follows}">${follows?"Following":"Follow"}</button><button id="open-report" class="primary-button">Download report</button></div></div></header><div class="key-facts"><div class="key-fact"><span>Severity</span><strong>${h(r.severity)}</strong></div><div class="key-fact"><span>Exploit evidence</span><strong>${h(r.exploitation.status)}</strong></div><div class="key-fact"><span>CISA KEV</span><strong>${h(kevStatus)}</strong></div></div><div class="tabs" role="tablist" aria-label="Vulnerability information">${views.map(([id,label])=>`<button role="tab" id="tab-${id}" data-view="${id}" aria-controls="panel-${id}" aria-selected="${activeView===id}" tabindex="${activeView===id?0:-1}">${label}</button>`).join("")}</div>${views.map(([id])=>`<div class="tab-panel" role="tabpanel" id="panel-${id}" aria-labelledby="tab-${id}" ${activeView!==id?"hidden":""}>${panels[id]}</div>`).join("")}`;
  $("#follow").addEventListener("click",()=>{saved.followed=follows?saved.followed.filter(id=>id!==r.id):[...saved.followed,r.id];persist();renderWorkspace();});
  $("#open-report").addEventListener("click",()=>{$("#report-author").value="";$("#report-scope").value="brief";$("#report-feedback").textContent="";$("#report-description").textContent=`${r.id}: ${r.title}`;$("#report-dialog").showModal();});
}
function showView(id) {
  if(!views.some(([view])=>view===id))return;
  activeView=id;
  for(const [view] of views) {
    const active=view===id;
    $(`#tab-${view}`).setAttribute("aria-selected",String(active));
    $(`#tab-${view}`).tabIndex=active?0:-1;
    $(`#panel-${view}`).hidden=!active;
  }
  $(`#tab-${id}`).focus();
}
function download(content,type,filename) {
  const url=URL.createObjectURL(new Blob([content],{type})),anchor=document.createElement("a");
  anchor.href=url;anchor.download=filename;document.body.append(anchor);anchor.click();anchor.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
}
function refreshEvidencePanel(panel) {
  const record=snapshot.records.find(r=>r.id===selected);
  $(`#panel-${panel}`).innerHTML=panel==="timeline"?renderTimeline(record,eventFilters):renderExploits(record,leadFilters);
}
function renderSnapshot() {
  const currentProduct=$("#product").value;
  const health=snapshot.health||[],success=health.filter(s=>s.status==="ok"),errors=health.filter(s=>s.status==="error");
  const stale=success.some(s=>Date.now()-Date.parse(s.lastSuccess)>12*3600000);
  $("#freshness").textContent=errors.length?`${errors.length} source check${errors.length===1?"":"s"} unavailable`:!success.length?"Automatic updates not started":stale?"Updates are overdue":"Up to date";
  $("#collection-detail").textContent=success.length?`Last update: ${date(snapshot.generatedAt)}`:"Showing reviewed starting data";
  $("#product").innerHTML='<option value="">All products</option>'+[...new Set(snapshot.records.map(r=>r.product))].sort().map(p=>`<option value="${h(p)}">${h(p)}</option>`).join("");
  if(snapshot.records.some(r=>r.product===currentProduct))$("#product").value=currentProduct;
  $("#health-count").textContent=success.length?`${success.length}/${health.length} checked`:"Not started";
  $("#health-list").innerHTML=health.map(s=>`<div class="health-row" data-state="${h(s.status)}"><strong>${h(s.name)} / ${h(s.status==="ok"?"Checked":s.status==="error"?"Unavailable":"Not checked yet")}</strong><span>Last successful check: ${h(date(s.lastSuccess))}${s.error?`<br>${h(s.error)}`:""}</span></div>`).join("");
  const candidates=snapshot.candidates||[];
  $("#candidate-count").textContent=String(candidates.length);
  $("#candidates").innerHTML=candidates.slice(0,30).map(c=>`<div class="candidate-row"><strong>${link(c.url,c.id)}</strong><span>${h(c.product)} / ${h(c.relationship)}. Found ${h(date(c.firstSeen))}${c.relatedTo?.length?` / Co-mentioned with ${h(c.relatedTo.join(", "))}`:""}</span></div>`).join("")||"<p>No new CVEs found yet.</p>";
  let hash=""; try { hash=decodeURIComponent(location.hash.slice(1)); } catch { /* Invalid links fall back to the first record. */ }
  selected=snapshot.records.some(r=>r.id===hash)?hash:snapshot.records[0]?.id;
  renderWorkspace();
}

document.addEventListener("click",async event=>{
  const target=event.target;
  const selectButton=target.closest("[data-select]"); if(selectButton)select(selectButton.dataset.select);
  const tab=target.closest("[data-view]"); if(tab)showView(tab.dataset.view);
  const pageButton=target.closest("[data-lead-page]");if(pageButton){leadFilters.page=Math.max(0,Number(pageButton.dataset.leadPage));refreshEvidencePanel("exploits");}
  const eventPage=target.closest("[data-event-page]");if(eventPage){eventFilters.page=Math.max(0,Number(eventPage.dataset.eventPage));refreshEvidencePanel("timeline");}
  if(target.closest("#export-timeline"))download(timelineCsv(timelineEvents(snapshot.records.find(r=>r.id===selected),eventFilters)),"text/csv;charset=utf-8",`${selected}-timeline.csv`);
  const controlButton=target.closest("[data-copy-control]");
  if(controlButton){try{await navigator.clipboard.writeText(snapshot.records.find(r=>r.id===selected).controls[Number(controlButton.dataset.copyControl)].query);notice("Candidate copied. Review its scope and validation plan before use.");}catch{notice("Select and copy the visible candidate.");}}
  const copyButton=target.closest("[data-copy-query]");
  if(copyButton) {
    const r=snapshot.records.find(r=>r.id===selected);
    try { await navigator.clipboard.writeText(r.detections[Number(copyButton.dataset.copyQuery)].query); notice("Query copied."); }
    catch { notice("Clipboard access is unavailable. Select and copy the visible query."); }
  }
});
document.addEventListener("change",event=>{
  const id=event.target.id;
  if(id==="timeline-kind"||id==="timeline-evidence"){eventFilters[id==="timeline-kind"?"kind":"evidence"]=event.target.value;eventFilters.page=0;refreshEvidencePanel("timeline");$(`#${id}`).focus();}
  if(id==="lead-kind"||id==="lead-older"||id==="lead-broad"){leadFilters[id==="lead-kind"?"kind":id==="lead-broad"?"broad":"older"]=id==="lead-kind"?event.target.value:event.target.checked;leadFilters.page=0;refreshEvidencePanel("exploits");$(`#${id}`).focus();}
});
document.addEventListener("input",event=>{
  if(event.target.id!=="lead-search")return;
  const start=event.target.selectionStart,end=event.target.selectionEnd;
  leadFilters.query=event.target.value;leadFilters.page=0;refreshEvidencePanel("exploits");$("#lead-search").focus();$("#lead-search").setSelectionRange(start,end);
});
document.addEventListener("keydown",event=>{
  const tab=event.target.closest("[data-view]");
  if(tab&&["ArrowLeft","ArrowRight","Home","End"].includes(event.key)) {
    event.preventDefault();
    const current=views.findIndex(([id])=>id===tab.dataset.view);
    const next=event.key==="Home"?0:event.key==="End"?views.length-1:(current+(event.key==="ArrowRight"?1:-1)+views.length)%views.length;
    showView(views[next][0]);
  }
});
$("#search").addEventListener("input",()=>snapshot&&renderWorkspace());
for(const id of ["#scope","#product"])$(id).addEventListener("change",()=>snapshot&&renderWorkspace());
$("#reset-filters").addEventListener("click",()=>{resetFilters();if(snapshot)renderWorkspace();});
$("#method-button").addEventListener("click",()=>$("#method-dialog").showModal());
document.querySelector('a[href="#health"]').addEventListener("click",()=>$("#health").open=true);
$("#clear-local").addEventListener("click",()=>{saved={followed:[],seen:{},exports:{}};for(const key of Object.keys(seenOnArrival))delete seenOnArrival[key];try{localStorage.removeItem(storageKey);}catch{/* Storage may be blocked. */}if(snapshot)renderWorkspace();notice("Saved preferences cleared.");});
for(const id of ["#export-word","#export-pdf"])$(id).addEventListener("click",()=>{
  const record=snapshot.records.find(r=>r.id===selected);
  const report=buildReport(record,snapshot,{scope:$("#report-scope").value,previousExport:saved.exports[record.id],author:$("#report-author").value});
  if(id==="#export-word") {
    const blob=new Blob([createDocx(report)],{type:"application/vnd.openxmlformats-officedocument.wordprocessingml.document"});
    const url=URL.createObjectURL(blob),a=document.createElement("a");
    a.href=url;a.download=`${record.id}-${report.scope}-report-${report.generatedAt.slice(0,10)}.docx`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
    saved.exports[record.id]={at:report.generatedAt,revision:record.revision};persist();
    $("#report-feedback").textContent="Word download requested. Your next update report will compare against this version.";
  } else {
    const win=window.open("","_blank");
    if(!win){$("#report-feedback").textContent="Allow pop-ups for this site to open the printable report.";return;}
    win.opener=null;win.document.write(reportHtml(report));win.document.close();
    $("#report-feedback").textContent="Report opened. Choose Print / save PDF in that tab. Your previous Word-export baseline is unchanged.";
  }
});
$("#export-json").addEventListener("click",()=>{
  const record=snapshot.records.find(r=>r.id===selected);
  download(evidenceJson(record,snapshot,{scope:$("#report-scope").value,previousExport:saved.exports[record.id]}),"application/json",`${record.id}-evidence.json`);
  $("#report-feedback").textContent="Evidence download requested. Your Word-export baseline is unchanged.";
});
const responseTag=response=>response.headers.get("etag")||response.headers.get("last-modified")||"";
async function checkForUpdate() {
  if(document.hidden||refreshing||Date.now()-lastUpdateCheck<5*60000)return;
  lastUpdateCheck=Date.now();
  try {
    const response=await fetch("./data.json",{method:"HEAD",cache:"no-cache"});
    const tag=responseTag(response);
    if(response.ok&&snapshotTag&&tag&&tag!==snapshotTag){$("#refresh-data").textContent="Update dashboard";$("#refresh-data").classList.add("primary-button");}
  } catch { /* Keep the current snapshot and allow a manual retry. */ }
}
$("#refresh-data").addEventListener("click",async()=>{
  if(refreshing)return;
  if(document.querySelector("dialog[open]")){notice("Close the report options before updating the dashboard.");return;}
  refreshing=true;$("#refresh-data").disabled=true;
  const scroll=window.scrollY;
  try {
    const response=await fetch("./data.json",{cache:"no-cache"});
    if(!response.ok)throw new Error("Snapshot unavailable");
    const value=await response.json();
    if(value.schemaVersion!==1||!Array.isArray(value.records)||!value.records.length)throw new Error("Unsupported snapshot");
    snapshot=value;snapshotTag=responseTag(response);renderSnapshot();window.scrollTo({top:scroll});
    $("#refresh-data").textContent="Check for updates";$("#refresh-data").classList.remove("primary-button");notice("Dashboard updated.");
  } catch { notice("Could not update. The current information has been kept."); }
  finally {refreshing=false;$("#refresh-data").disabled=false;}
});
setInterval(checkForUpdate,15*60000);
document.addEventListener("visibilitychange",()=>{if(!document.hidden)checkForUpdate();});
try {
  const response=await fetch("./data.json",{cache:"no-cache"});
  if(!response.ok)throw new Error(`Request returned ${response.status}`);
  snapshot=await response.json();
  snapshotTag=responseTag(response);
  if(snapshot.schemaVersion!==1||!Array.isArray(snapshot.records)||!snapshot.records.length)throw new Error("Unsupported or empty data");
  renderSnapshot();
} catch(error) {
  $("#freshness").textContent="Data unavailable";$("#collection-detail").textContent="Reload to try again.";
  $("#brief").innerHTML=`<p class="empty">Unable to load vulnerability data. ${h(error.message)}</p>`;
}
