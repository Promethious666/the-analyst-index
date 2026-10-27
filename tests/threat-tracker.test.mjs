import assert from "node:assert/strict";
import {readFile,writeFile,mkdir} from "node:fs/promises";
import test from "node:test";
import {buildReport,filterRecords,reportHtml,safeUrl,timelineEvents,timelineCsv,evidenceJson,researchQueue,classifyLead} from "../public/threat-tracker/core.mjs";
import {createDocx,docxFiles} from "../public/threat-tracker/word.mjs";

const briefs=JSON.parse(await readFile(new URL("../public/threat-tracker/briefs.json",import.meta.url),"utf8"));
const record={...briefs.records[0],revision:"current",live:{leads:[{title:"Unreviewed repository",url:"https://example.com/repository",kind:"Repository mention"}]}};
const snapshot={generatedAt:"2026-10-26T10:00:00Z",records:[record],health:[{name:"CISA KEV",status:"error",lastSuccess:"2026-10-25T10:00:00Z",error:"HTTP 503"}]};

test("search combines product, keywords, local watchlist and revision changes",()=>{
  const records=[record,{...briefs.records[2],revision:"php"}];
  assert.equal(filterRecords(records,{query:"brotli Node.js"}).length,1);
  assert.equal(filterRecords(records,{product:"PHP"})[0].id,"CVE-2026-109619");
  assert.equal(filterRecords(records,{scope:"followed",followed:[record.id]}).length,1);
  assert.equal(filterRecords(records,{scope:"changed",seen:{[record.id]:"older"}}).length,1);
  assert.equal(filterRecords(records,{scope:"changed",seen:{}}).length,0);
});

test("reports retain evidence limitations, provenance, queries and failed-source status",()=>{
  const report=buildReport(record,snapshot,{now:"2026-10-26T11:00:00Z"});
  const content=JSON.stringify(report);
  for(const text of ["Organisational exposure: not assessed", "HTTP 503", "Unreviewed repository", "Researcher-demonstrated", "CveId", "https://nodejs.org/"])assert.ok(content.includes(text),text);
  assert.ok(!content.includes("Listed as known exploited"));
});

test("update reports recognise an unchanged export and preserve the current assessment",()=>{
  const report=buildReport(record,snapshot,{scope:"update",previousExport:{at:"2026-10-25T12:00:00Z",revision:"current"}});
  assert.match(JSON.stringify(report),/No material evidence changes/);
  assert.ok(report.sections.some(x=>x.heading==="Mitigations and control coverage"));
  assert.ok(!report.sections.find(x=>x.heading==="Recorded developments").lines.some(x=>x.includes("2026-10-21")));
});

test("untrusted values are escaped in print exports and unsafe links rejected",()=>{
  const report=buildReport({...record,title:'<script>alert("x")</script>'},snapshot,{author:'<img src=x onerror=alert(1)>'});
  const html=reportHtml(report);
  assert.ok(!html.includes('<script>alert("x")</script>'));
  assert.ok(html.includes("&lt;script&gt;"));
  assert.equal(safeUrl("javascript:alert(1)"),"");
  assert.equal(safeUrl("https://user:password@example.com"),"");
  assert.equal(safeUrl("http://example.com"),"");
});

test("Word exports contain a real OOXML package with explicit author metadata only",async()=>{
  const report=buildReport(record,snapshot,{author:"Adam Brown"});
  const files=docxFiles(report),bytes=createDocx(report);
  assert.equal(new DataView(bytes.buffer).getUint32(0,true),0x04034b50);
  assert.match(files["docProps/core.xml"],/<dc:creator>Adam Brown<\/dc:creator>/);
  assert.ok(!docxFiles(buildReport(record,snapshot))["docProps/core.xml"].includes("dc:creator"));
  assert.ok(files["word/document.xml"].includes("wordprocessingml/2006/main"));
  assert.ok(!Object.keys(files).some(x=>x.includes("vba")||x.includes("external")));
  if(process.env.REPORT_TEST_PATH){await mkdir(process.env.REPORT_TEST_PATH,{recursive:true});await writeFile(`${process.env.REPORT_TEST_PATH}/tracker-report.docx`,bytes);await writeFile(`${process.env.REPORT_TEST_PATH}/tracker-report.html`,reportHtml(report));}
});

test("reviewed briefs cite the evidence for relationships and avoid invented IOCs",()=>{
  for(const r of briefs.records){
    assert.ok(r.sources.length);assert.equal(r.iocs.length,0);
    for(const relation of r.related)assert.ok(safeUrl(relation.source));
    for(const source of r.sources)assert.ok(safeUrl(source.url));
  }
});

test("late discovery of an older event appears in change reports with its source",()=>{
  const late={...record,live:{timeline:[{id:"late",at:"2026-10-01",firstSeen:"2026-10-26T09:00:00Z",kind:"upstream-report",title:"Older report found today",url:"https://example.org/report",sourceField:"datePublic"}]}};
  const report=buildReport(late,snapshot,{scope:"update",previousExport:{at:"2026-10-25T10:00:00Z",revision:"old"}});
  const section=report.sections.find(s=>s.heading==="Recorded developments").lines.join("\n");
  assert.match(section,/Older report found today/);assert.match(section,/Needs review/);assert.match(section,/https:\/\/example.org\/report/);
  assert.match(section,/2026-10-01/);assert.match(section,/2026-10-26/);
  assert.ok(!timelineEvents(late,{evidence:"reviewed"}).some(e=>e.id==="late"));
});

test("CSV protects spreadsheet formulas and preserves quoted source content",()=>{
  const csv=timelineCsv([{at:"2026-10-26",title:'=HYPERLINK("evil")',detail:'comma, quote " and newline\n',reviewStatus:"Needs review"}]);
  assert.ok(csv.includes(`"'=HYPERLINK(""evil"")"`));assert.ok(csv.includes('comma, quote "" and newline\n'));
});

test("full exports include reviewed revisions, control gaps and structured evidence",()=>{
  const report=buildReport(record,snapshot);
  assert.match(JSON.stringify(report),/452151d4945c3f5d9b58d9d25792d0d8aef4ab16/);
  assert.ok(report.sections.some(s=>s.heading==="Outstanding research"));
  assert.ok(report.sections.some(s=>s.heading==="Attack paths and control evidence"));
  const json=JSON.parse(evidenceJson(record,snapshot));
  assert.equal(json.brief.id,record.id);assert.equal(json.collection.health[0].error,"HTTP 503");
  assert.ok(researchQueue(record).untestedControls.length>0);
});

test("Brotli candidate evaluates coding tokens and remains in count mode",()=>{
  const rule=JSON.parse(briefs.records[0].controls.find(c=>c.language==="AWS WAF JSON").query);
  assert.deepEqual(rule.Action,{Count:{}});
  const regex=new RegExp(rule.Statement.RegexMatchStatement.RegexString,"i");
  for(const value of ["br","BR","gzip, br","br, gzip"," gzip ,\tbr "])assert.ok(regex.test(value),value);
  for(const value of ["gzip","bravo","xbr","b r",""])assert.ok(!regex.test(value),value);
});

test("discovery triage separates metadata candidates without promoting them to evidence",()=>{
  assert.equal(classifyLead({title:"General security news",description:"Tracks every CVE",kind:"Repository mention"},record).direct,false);
  assert.equal(classifyLead({title:`${record.id}-checker`,kind:"Repository mention"},record).type,"checkers");
  assert.equal(classifyLead({title:`${record.id}-patch`,kind:"Repository mention"},record).type,"patches");
  assert.equal(classifyLead({title:`${record.id}-poc`,kind:"Repository mention"},record).label,"Claimed PoC");
});

test("summary reports stay focused and retain control limitations",()=>{
  const large={...record,live:{timeline:Array.from({length:500},(_,i)=>({id:String(i),at:"2026-10-26",title:"Unreviewed",detail:"Noisy source entry"})),leads:Array.from({length:200},(_,i)=>({title:String(i),kind:"Repository mention",url:`https://example.org/${i}`}))}};
  const report=buildReport(large,snapshot,{scope:"brief"});
  const content=JSON.stringify(report);
  assert.ok(content.length<12000);assert.ok(!content.includes("Noisy source entry"));
  assert.match(content,/external response/);assert.match(content,/not independently|No independent/);
  assert.ok(docxFiles(report)["word/document.xml"].includes("Summary report"));
});

test("summary and technical reports carry newer KEV and dated EPSS evidence",()=>{
  const current={...record,live:{kev:{listed:true,checkedAt:"2026-10-27T10:00:00Z"},epss:{score:0.42,date:"2026-10-27"}}};
  for(const scope of ["brief","full","update"]){
    const report=JSON.stringify(buildReport(current,snapshot,{scope}));
    assert.match(report,/Listed as known exploited/);assert.match(report,/2026-10-27T10:00:00Z/);
    assert.match(report,/42.00% predicted/);assert.match(report,/this is a prediction/);
    assert.match(report,/cisa.gov/);assert.match(report,/first.org/);
  }
});
