import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const html = readFileSync(new URL("../docs/threat-tracker/daily.html", import.meta.url), "utf8");
const seed = JSON.parse(html.match(/id="snapshot" type="application\/json">([\s\S]*?)<\/script>/)[1]);
const script = html.match(/<script>([\s\S]*?)<\/script>/)[1];
const published = JSON.parse(readFileSync(new URL("../docs/threat-tracker/daily-data.json", import.meta.url)));

class Element {
  constructor() { this.children = []; this.value = ""; this.textContent = ""; }
  append(child) { this.children.push(child); }
  replaceChildren() { this.children = []; }
}
function open(search) {
  const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
  const get = id=>elements.get(id);
  get("snapshot").textContent = JSON.stringify(seed);
  const document = {getElementById:get,createElement:()=>new Element()};
  runInNewContext(script, {document, URL, URLSearchParams, history:{replaceState(){}}, location:{protocol:"https:",hash:"",search}});
  return get;
}

test("portable and published daily archives contain the same incidents", ()=>{
  assert.deepEqual(published,seed);
});
test("one day shows only that day's evidence, and incident navigation skips quiet days", ()=>{
  const get = open("?day=2026-11-18&incident=CVE-2026-114938");
  const cards = ()=>JSON.stringify(get("briefs").children);
  assert.equal(get("briefs").children.length,1);
  assert.match(cards(),/Temurin lists fixed builds/);
  assert.doesNotMatch(cards(),/Oracle issued/);
  get("next").onclick();
  assert.equal(get("day").value,"2026-11-19");
  assert.match(cards(),/Oracle issued/);
  get("day").value="2026-11-01";get("day").onchange();
  assert.equal(get("briefs").children.length,0);
  get("latest").onclick();
  assert.match(cards(),/Oracle issued/);
});
