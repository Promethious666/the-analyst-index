import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {runInNewContext} from "node:vm";

const html=readFileSync(new URL("../docs/threat-tracker/inbox.html",import.meta.url),"utf8");
const script=html.match(/<script>([\s\S]*?)<\/script>/)[1];
const seed=JSON.parse(html.match(/id="snapshot">([\s\S]*?)<\/script>/)[1]);
const published=JSON.parse(readFileSync(new URL("../docs/threat-tracker/inbox-data.json",import.meta.url),"utf8"));

class Element {
  constructor(){this.children=[];this.dataset={};this.value="";this.textContent="";}
  append(child){this.children.push(child);}
  replaceChildren(){this.children=[];}
  setAttribute(){}
  addEventListener(){}
  querySelector(){return null;}
}

test("the page and the public refresh feed contain the same starting collection",()=>{
  assert.deepEqual(published,seed);
});

test("an open or returning tab picks up newer reports and keeps its last collection on failure",async()=>{
  const id="CVE-2026-114938";
  const original=seed.items.find(i=>i.id===id);
  const elements=new Map([...html.matchAll(/id="([^"]+)"/g)].map(m=>[m[1],new Element()]));
  const get=id=>elements.get(id);
  get("snapshot").textContent=JSON.stringify(seed);
  get("find").value="Java4Shell";
  let now=Date.parse(seed.generatedAt)+60*60*1000;
  let next=seed,requests=0,tick,visibility;
  class Clock extends Date{static now(){return now;}}
  const document={hidden:false,getElementById:get,createElement:()=>new Element(),
    addEventListener:(event,fn)=>{if(event==="visibilitychange")visibility=fn;}};
  const ctx={document,Date:Clock,Intl,URL,history:{replaceState(){}},location:{protocol:"https:",hash:"#"+id},
    localStorage:{getItem:()=>null},setInterval:fn=>{tick=fn;},
    fetch:async(url,options)=>{
      assert.equal(url,"./inbox-data.json");assert.equal(options.credentials,"omit");requests++;
      if(next===null)throw Error("Offline");
      return {ok:true,json:async()=>next};
    }};
  runInNewContext(script,ctx);
  const settle=()=>new Promise(resolve=>setImmediate(resolve));
  await settle();assert.equal(requests,1);
  const selectedTitle=()=>get("detail").children[1].textContent;
  assert.equal(selectedTitle(),original.title);
  next={...seed,generatedAt:new Date(now).toISOString(),items:[{...original,title:"Java4Shell updated"}]};
  document.hidden=true;now+=300001;tick();await settle();assert.equal(requests,1);
  document.hidden=false;visibility();await settle();assert.equal(selectedTitle(),"Java4Shell updated");
  assert.equal(get("find").value,"Java4Shell");
  next=null;now+=300001;tick();await settle();
  assert.equal(selectedTitle(),"Java4Shell updated");assert.match(get("notice").textContent,/will retry/);
  next=seed;now+=300001;tick();await settle();
  assert.equal(selectedTitle(),"Java4Shell updated");assert.equal(get("notice").textContent,"");
});
