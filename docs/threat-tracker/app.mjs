import {escapeHtml as h,safeUrl,filterRecords,buildReport,reportHtml} from "./core.mjs";
import {createDocx} from "./word.mjs";

const $=selector=>document.querySelector(selector);
const storageKey="threat-tracker-preferences-v1";
let saved={followed:[],seen:{},exports:{}};
try{const value=JSON.parse(localStorage.getItem(storageKey)||"null");if(value&&Array.isArray(value.followed)&&value.seen&&typeof value.seen==="object"&&value.exports&&typeof value.exports==="object")saved=value;}catch{/* Preferences are optional. */}
const seenOnArrival={...saved.seen};
let snapshot=null,selected=null,noticeTimer;
const date=value=>value&&!Number.isNaN(Date.parse(value))?new Intl.DateTimeFormat("en-GB",{dateStyle:"medium",...(value.length>10?{timeStyle:"short"}:{}),timeZone:"Europe/London"}).format(new Date(value))+(value.length>10?" UK":""):"Not recorded";
const link=(url,title)=>{const valid=safeUrl(url);return valid?`<a href="${h(valid)}" target="_blank" rel="noopener noreferrer">${h(title)}</a>`:h(title);};
function notice(message){$("#notice").textContent=message;$("#notice").hidden=false;clearTimeout(noticeTimer);noticeTimer=setTimeout(()=>$("#notice").hidden=true,5000);}
function persist(){try{localStorage.setItem(storageKey,JSON.stringify(saved));return true;}catch{notice("Browser storage is unavailable. Your preferences will last for this visit only.");return false;}}
function list(items){return `<ul>${items.map(x=>`<li>${h(x)}</li>`).join("")}</ul>`;}
function section(title,content){return `<section class="brief-section"><h3>${h(title)}</h3>${content}</section>`;}

function renderList(){
  const found=filterRecords(snapshot.records,{query:$("#search").value,product:$("#product").value,scope:$("#scope").value,followed:saved.followed,seen:seenOnArrival});
  $("#result-count").textContent=String(found.length);
  $("#records").innerHTML=found.length?found.map(r=>`<div class="record ${r.id===selected?"selected":""}"><button data-select="${h(r.id)}" ${r.id===selected?'aria-current="true"':""}><span class="cve">${h(r.id)}</span><h3>${h(r.title)}</h3><p>${h(r.product)} · Reviewed ${h(r.reviewedAt.slice(0,10))}</p><div class="record-bottom"><span class="tag ${h(r.severity.toLowerCase())}">${h(r.severity)}</span>${seenOnArrival[r.id]&&seenOnArrival[r.id]!==r.revision?'<span class="tag changed">Updated</span>':saved.followed.includes(r.id)?'<span class="tag reviewed">Following</span>':""}</div></button></div>`).join(""):'<p class="empty">No matching vulnerabilities. Try another search or reset the filters.</p>';
}

function renderBrief(){
  const r=snapshot.records.find(x=>x.id===selected);
  if(!r){$("#brief").innerHTML='<p class="empty">Choose a vulnerability to open its brief.</p>';return;}
  saved.seen[r.id]=r.revision;persist();
  const live=r.live||{};
  const sourceLink=id=>{const source=r.sources.find(s=>s.id===id);return source?link(source.url,source.title):"";};
  const follows=saved.followed.includes(r.id);
  const requirements=section("Exploitation requirements",`<p>${h(r.technical)}</p>${list(r.requirements)}<p class="small">${r.exploitation.sourceIds.map(sourceLink).filter(Boolean).join(" · ")}</p>`);
  const fixes=section("Affected versions and fixes",`<dl class="facts">${r.affected.map(a=>`<div class="fact"><dt>${h(a.product)}</dt><dd>${h(a.range)}<br><strong>Fix: ${h(a.fixed)}</strong></dd></div>`).join("")}</dl><p class="small">${r.sources.filter(s=>s.type==="Vendor advisory").map(s=>link(s.url,s.title)).join(" · ")}</p>`);
  const kev=live.kev?.checkedAt?`<p><strong>CISA KEV:</strong> ${live.kev.listed?"Listed as known exploited":"Not listed in the retrieved catalogue"}. Checked ${h(date(live.kev.checkedAt))}. Absence from this catalogue does not rule out exploitation.</p>`:'<p>CISA KEV status has not been collected successfully.</p>';
  const evidence=section("Exploitation evidence",`<span class="tag reviewed">${h(r.exploitation.status)}</span><p style="margin-top:12px">${h(r.exploitation.detail)}</p>${kev}${live.epss?`<p><strong>EPSS:</strong> ${(Number(live.epss.score)*100).toFixed(2)}% estimated probability over the next 30 days; score date ${h(live.epss.date)}. This is a prediction, not evidence of exploitation.</p>`:""}`);
  const mitigation=section("Mitigations and control coverage",r.mitigations.map(m=>`<div class="callout"><strong>${h(m.action)}</strong><p>${h(m.coverage)}</p><p><strong>Limit:</strong> ${h(m.limitation)}</p></div>`).join(""));
  const detections=section("Detection and investigation",r.detections.map((d,i)=>`<div><h3>${h(d.title)}</h3><span class="tag">${h(d.status)}</span><p><strong>Requires:</strong> ${h(d.requirements)}<br><strong>Limit:</strong> ${h(d.limitation)}</p>${d.query?`<details><summary>View hunting query</summary><p class="small">Review the required table permissions and product naming before running.</p><pre class="code-block"><code>${h(d.query)}</code></pre><button class="quiet-button" data-copy-query="${i}">Copy query</button></details>`:""}</div>`).join("<hr>"));
  const iocs=section("IOCs",r.iocs.length?list(r.iocs.map(i=>`${i.value}: ${i.context}. Source: ${i.source}`)):'<p>No validated CVE-specific IOCs are included. A crash or a generic process event alone does not establish exploitation.</p>');
  const related=section("Related vulnerabilities",r.related.length?r.related.map(x=>`<div class="source"><strong>${h(x.id)}</strong><p>${h(x.relationship)}</p>${link(x.source,"Relationship evidence")}${snapshot.records.some(t=>t.id===x.id)?` · <button class="text-button" data-select="${h(x.id)}">Open tracked brief</button>`:""}</div>`).join(""):'<p>No evidence-backed relationships recorded.</p>');
  const leadLinks=(live.leads||[]).map(x=>`<div class="source">${link(x.url,x.title)}<span class="meta">${h(x.kind)} · Unreviewed · First seen ${h(date(x.firstSeen))}</span></div>`).join("");
  const refs=(live.references||[]).map(x=>`<div class="source">${link(x,x)}<span class="meta">CVE record reference · Unreviewed</span></div>`).join("");
  const leads=section("Automatically collected leads",`<div class="callout warning"><p>These are leads for investigation. A repository mentioning a CVE is not a verified PoC. A matching template is not proof of effective detection or blocking.</p></div>${leadLinks||'<p>No repository or rule leads collected.</p>'}${refs?`<details><summary>CVE record references (${(live.references||[]).length})</summary>${refs}</details>`:""}`);
  const timeline=section("Recorded developments",`<ol class="timeline">${[...(r.history||[])].reverse().map(e=>`<li><time datetime="${h(e.at)}">${h(date(e.at))}</time><strong>${h(e.title)}</strong><p>${h(e.detail||"")}${e.url?` ${link(e.url,"Source")}`:""}</p></li>`).join("")}</ol>`);
  const sources=section("Reviewed sources",r.sources.map(s=>`<div class="source">${link(s.url,s.title)}<span class="meta">${h(s.publisher)} · ${h(s.type)} · Reviewed ${h(s.reviewedAt)}</span></div>`).join(""));
  $("#brief").innerHTML=`<header class="brief-header"><p class="eyebrow">${h(r.id)} / ${h(r.product)}</p><h2>${h(r.title)}</h2><p>${h(r.summary)}</p><div class="badge-row"><span class="tag">${h(r.severity)} · ${h(r.severityBasis)}</span><span class="tag">Brief reviewed ${h(r.reviewedAt.slice(0,10))}</span></div><div class="action-row"><button id="follow" class="quiet-button" aria-pressed="${follows}">${follows?"Following":"Follow vulnerability"}</button><button id="open-report" class="primary-button">Export report <span aria-hidden="true">↗</span></button></div></header><div class="brief-body"><div class="callout"><strong>Next useful action</strong><p>${h(r.nextAction)}</p></div>${fixes}${requirements}${evidence}${mitigation}${detections}${iocs}${related}${timeline}${leads}${sources}<p class="small">Collection and technical review are separate. Organisational exposure: not assessed.</p></div>`;
  $("#follow").addEventListener("click",()=>{saved.followed=follows?saved.followed.filter(id=>id!==r.id):[...saved.followed,r.id];persist();renderBrief();renderList();});
  $("#open-report").addEventListener("click",()=>{$("#report-author").value="";$("#report-scope").value="full";$("#report-feedback").textContent="";$("#report-description").textContent=`${r.id}: ${r.title}. Export the evidence, sources and collection status shown in this snapshot.`;$("#report-dialog").showModal();});
}

function select(id){if(!snapshot.records.some(r=>r.id===id))return;selected=id;history.replaceState(null,"",`#${encodeURIComponent(id)}`);renderList();renderBrief();}
function renderSnapshot(){
  const health=snapshot.health||[],success=health.filter(s=>s.status==="ok"),errors=health.filter(s=>s.status==="error");
  const stale=success.some(s=>Date.now()-Date.parse(s.lastSuccess)>12*3600000);
  $("#freshness").textContent=errors.length?"Collection needs attention":!success.length?"Initial reviewed snapshot":stale?"Evidence collection is stale":"Latest collection available";
  $("#collection-detail").textContent=`Snapshot: ${date(snapshot.generatedAt)}. ${success.length} of ${health.length} source checks succeeded. Briefs retain their own review dates.`;
  $("#stats").innerHTML=[[snapshot.records.length,"tracked vulnerabilities"],[new Set(snapshot.records.map(r=>r.product)).size,"monitored products"],[snapshot.records.reduce((n,r)=>n+(r.live?.leads||[]).length,0),"unreviewed research leads"],[success.length+"/"+health.length,"successful source checks"]].map(([count,title])=>`<div class="stat"><strong>${h(count)}</strong><span>${h(title)}</span></div>`).join("");
  $("#product").innerHTML='<option value="">All products</option>'+[...new Set(snapshot.records.map(r=>r.product))].sort().map(p=>`<option value="${h(p)}">${h(p)}</option>`).join("");
  $("#health-list").innerHTML=health.map(s=>`<div class="health-row" data-state="${h(s.status)}"><strong>${h(s.name)} · ${h(s.status==="ok"?"Collected":s.status==="error"?"Failed":"Not collected")}</strong><span>Last success: ${h(date(s.lastSuccess))}${s.error?`<br>${h(s.error)}`:""}</span></div>`).join("")||'<p>No automated collection has run yet.</p>';
  $("#candidates").innerHTML=(snapshot.candidates||[]).slice(0,30).map(c=>`<div class="candidate-row"><strong>${link(c.url,c.id)}</strong><span>${h(c.product)} · Shared monitored source; relationship unreviewed.<br>First seen: ${h(date(c.firstSeen))}</span></div>`).join("")||'<p>No additional CVE candidates discovered yet.</p>';
  let hash="";try{hash=decodeURIComponent(location.hash.slice(1));}catch{/* Invalid links fall back to the first record. */}
  select(snapshot.records.some(r=>r.id===hash)?hash:snapshot.records[0]?.id);
}

document.addEventListener("click",async event=>{
  const selectButton=event.target.closest("[data-select]");if(selectButton)select(selectButton.dataset.select);
  const copyButton=event.target.closest("[data-copy-query]");if(copyButton){const r=snapshot.records.find(r=>r.id===selected);try{await navigator.clipboard.writeText(r.detections[Number(copyButton.dataset.copyQuery)].query);notice("Hunting query copied.");}catch{notice("Clipboard access is unavailable. Select and copy the visible query.");}}
});
$("#search").addEventListener("input",()=>snapshot&&renderList());
for(const id of ["#scope","#product"])$(id).addEventListener("change",()=>snapshot&&renderList());
$("#reset-filters").addEventListener("click",()=>{$("#search").value="";$("#scope").value="all";$("#product").value="";if(snapshot)renderList();});
$("#method-button").addEventListener("click",()=>$("#method-dialog").showModal());
$("#clear-local").addEventListener("click",()=>{saved={followed:[],seen:{},exports:{}};for(const key of Object.keys(seenOnArrival))delete seenOnArrival[key];try{localStorage.removeItem(storageKey);}catch{/* Storage may be blocked. */}if(snapshot){renderList();renderBrief();}notice("Local watchlists and export history cleared.");});
for(const id of ["#export-word","#export-pdf"])$(id).addEventListener("click",()=>{
  const record=snapshot.records.find(r=>r.id===selected);
  const report=buildReport(record,snapshot,{scope:$("#report-scope").value,previousExport:saved.exports[record.id],author:$("#report-author").value});
  if(id==="#export-word"){
    const blob=new Blob([createDocx(report)],{type:"application/vnd.openxmlformats-officedocument.wordprocessingml.document"});
    const url=URL.createObjectURL(blob),a=document.createElement("a");a.href=url;a.download=`${record.id}-${report.scope}-report-${report.generatedAt.slice(0,10)}.docx`;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),60000);
    saved.exports[record.id]={at:report.generatedAt,revision:record.revision};persist();$("#report-feedback").textContent="Word download requested. This snapshot is now the baseline for your next update report.";
  }else{
    const win=window.open("","_blank");if(!win){$("#report-feedback").textContent="Allow pop-ups for this site to open the printable report.";return;}
    win.opener=null;win.document.write(reportHtml(report));win.document.close();$("#report-feedback").textContent="Printable report opened. Use Print / save PDF in that tab. Your previous Word-export baseline is unchanged.";
  }
});
try{
  const response=await fetch("./data.json",{cache:"no-cache"});if(!response.ok)throw new Error(`Snapshot request returned ${response.status}`);
  snapshot=await response.json();if(snapshot.schemaVersion!==1||!Array.isArray(snapshot.records)||!snapshot.records.length)throw new Error("Unsupported or empty snapshot");renderSnapshot();
}catch(error){$("#freshness").textContent="Snapshot unavailable";$("#collection-detail").textContent="The latest evidence could not be loaded. Reload to try again.";$("#brief").innerHTML=`<p class="empty">Unable to load the published snapshot. ${h(error.message)}</p>`;}
