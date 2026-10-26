import assert from "node:assert/strict";
import {readFile,writeFile,mkdir} from "node:fs/promises";
import test from "node:test";
import {buildReport,filterRecords,reportHtml,safeUrl} from "../public/threat-tracker/core.mjs";
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
