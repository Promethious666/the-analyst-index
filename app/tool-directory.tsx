"use client";

import { useEffect, useMemo, useState } from "react";
import { categories, platforms, Tool, tools } from "./catalogue";

const quickAsks = ["Windows event logs", "Suspicious file", "Packet capture", "Cloud posture", "Threat intelligence"];
const workflowMap: Record<string, string[]> = {
  "Triage a Windows host": ["KAPE", "Eric Zimmerman Tools", "Chainsaw", "Hayabusa"],
  "Investigate a packet capture": ["Wireshark", "Zeek", "Brim", "RITA"],
  "Assess cloud posture": ["Prowler", "Scout Suite", "Cloudsplaining", "Cartography"],
  "Analyse suspicious malware": ["YARA", "FLOSS", "CAPA", "Ghidra"],
};

export function ToolDirectory() {
  const [query, setQuery] = useState("");
  const [interaction, setInteraction] = useState("All");
  const [data, setData] = useState("All");
  const [setup, setSetup] = useState("All");
  const [category, setCategory] = useState("All");
  const [platform, setPlatform] = useState("All");
  const [selected, setSelected] = useState<Tool | null>(null);
  const [compare, setCompare] = useState<string[]>([]);
  const [watchlist, setWatchlist] = useState<string[]>(() => {
    if (typeof window === "undefined") return [];
    try { return JSON.parse(localStorage.getItem("analyst-index-watchlist") || "[]"); } catch { return []; }
  });
  const [workflow, setWorkflow] = useState("All workflows");

  const matches = useMemo(() => {
    const terms = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
    const workflowNames = workflow === "All workflows" ? null : workflowMap[workflow];
    return tools.filter((tool) => {
      const haystack = `${tool.name} ${tool.category} ${tool.summary} ${tool.keywords} ${tool.platforms.join(" ")} ${tool.output}`.toLowerCase();
      return terms.every((term) => haystack.includes(term)) &&
        (interaction === "All" || tool.interaction === interaction) &&
        (data === "All" || tool.data === data) &&
        (setup === "All" || tool.setup === setup) &&
        (category === "All" || tool.category === category) &&
        (platform === "All" || tool.platforms.includes(platform)) &&
        (!workflowNames || workflowNames.includes(tool.name));
    });
  }, [query, interaction, data, setup, category, platform, workflow]);

  const reset = () => { setQuery(""); setInteraction("All"); setData("All"); setSetup("All"); setCategory("All"); setPlatform("All"); setWorkflow("All workflows"); };
  const toggleCompare = (name: string) => setCompare((current) => current.includes(name) ? current.filter((item) => item !== name) : current.length < 3 ? [...current, name] : current);
  const toggleWatch = (name: string) => setWatchlist((current) => {
    const next = current.includes(name) ? current.filter((item) => item !== name) : [...current, name];
    localStorage.setItem("analyst-index-watchlist", JSON.stringify(next));
    return next;
  });
  const compared = compare.map((name) => tools.find((tool) => tool.name === name)).filter(Boolean) as Tool[];

  return (
    <main className="site-shell" id="top">
      <header className="masthead">
        <a className="brand" href="#top"><span className="brand-mark">A/</span> THE ANALYST INDEX</a>
        <nav className="mast-links" aria-label="Primary navigation"><a href="#directory">Directory</a><a href="#method">Method</a><span><i className="status-dot" />111 reviewed entries</span></nav>
      </header>
      <section className="hero">
        <p className="eyebrow">Open-source security tools / with operational context</p>
        <h1>Find the right tool.<br /><span>Know the trade-offs.</span></h1>
        <p className="hero-copy">A decision-focused index for defenders. Start with the evidence or task you have, then compare interaction risk, data handling and setup burden before you install anything.</p>
        <div className="hero-stats" aria-label="Catalogue summary"><span><b>111</b> reviewed tools</span><span><b>{categories.length}</b> specialist areas</span><span><b>0</b> accounts or trackers</span></div>
      </section>
      <section className="finder" aria-label="Tool finder">
        <div className="finder-label"><label htmlFor="tool-search">What are you investigating?</label><span>LOCAL SEARCH / NO QUERY LOGGING</span></div>
        <div className="search-row"><input id="tool-search" type="search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Try: Windows event logs, packet capture, suspicious file…" autoComplete="off" /><button className="clear-button" type="button" onClick={reset}>Reset filters</button></div>
        <div className="quick-asks" aria-label="Example searches">{quickAsks.map((ask) => <button type="button" key={ask} onClick={() => setQuery(ask)}>{ask}</button>)}</div>
      </section>
      <section className="workspace" id="directory">
        <aside className="filters" aria-label="Directory filters">
          <h2>Refine the decision</h2>
          <Filter label="Guided workflow" value={workflow} onChange={setWorkflow} options={["All workflows", ...Object.keys(workflowMap)]} />
          <Filter label="Security area" value={category} onChange={setCategory} options={["All", ...categories]} />
          <Filter label="Platform" value={platform} onChange={setPlatform} options={["All", ...platforms]} />
          <Filter label="Target interaction" value={interaction} onChange={setInteraction} options={["All", "Passive", "Active", "Offline"]} />
          <Filter label="Evidence handling" value={data} onChange={setData} options={["All", "Local", "External", "Mixed"]} />
          <Filter label="Setup effort" value={setup} onChange={setSetup} options={["All", "Easy", "Moderate", "Advanced"]} />
          <p className="scope-note">Entries are navigation aids, not endorsements. Confirm upstream documentation and obtain authorisation before active use.</p>
        </aside>
        <div className="results">
          <div className="results-head"><div><p className="eyebrow">Decision workspace</p><h2>Shortlist</h2></div><p>{matches.length.toString().padStart(3, "0")} / {tools.length} tools</p></div>
          {compared.length > 0 && <section className="compare-tray" aria-label="Tool comparison"><div><b>Compare ({compared.length}/3)</b><span>{compared.map((tool) => tool.name).join(" · ")}</span></div><button type="button" onClick={() => setCompare([])}>Clear</button></section>}
          {compared.length > 1 && <Comparison tools={compared} onOpen={setSelected} />}
          <div className="tool-grid">
            {matches.map((tool) => <article className="tool-card" key={tool.name}>
              <div className="card-top"><div><p className="tool-type">{tool.category}</p><h3><button type="button" onClick={() => setSelected(tool)}>{tool.name}</button></h3></div><span className="format-badge">{tool.delivery}</span></div>
              <p className="summary">{tool.summary}</p>
              <div className="signals"><Signal label="Interaction" value={tool.interaction} /><Signal label="Data path" value={tool.data} /><Signal label="Setup" value={tool.setup} /><Signal label="Format" value={tool.delivery} /></div>
              <div className="card-actions"><button type="button" aria-pressed={compare.includes(tool.name)} onClick={() => toggleCompare(tool.name)}>{compare.includes(tool.name) ? "Comparing" : "Compare"}</button><button type="button" aria-pressed={watchlist.includes(tool.name)} onClick={() => toggleWatch(tool.name)}>{watchlist.includes(tool.name) ? "Saved" : "Save"}</button><button type="button" onClick={() => setSelected(tool)}>Details</button></div>
              <div className="card-foot"><span className="evidence">{tool.evidence} · {tool.reviewed}</span><a className="repo-link" href={tool.repo} target="_blank" rel="noreferrer">Repository ↗</a></div>
            </article>)}
            {matches.length === 0 && <div className="empty"><strong>No exact match yet.</strong><br />Broaden a filter or search by the evidence type you have.</div>}
          </div>
        </div>
      </section>
      <section className="principles" id="method">
        <p className="eyebrow">Method and boundaries</p><h2>Catalogue size is easy. Trustworthy context is the work.</h2>
        <div className="principle-grid">
          <div className="principle"><b>01 / PROVENANCE</b><h3>Claims stay labelled</h3><p>Repository evidence, machine-checked facts and analyst assessments remain distinct.</p></div>
          <div className="principle"><b>02 / OPERATIONS</b><h3>Risk before convenience</h3><p>Active interaction, external data transfer and setup assumptions are visible before the click.</p></div>
          <div className="principle"><b>03 / MAINTENANCE</b><h3>Last-known-good</h3><p>Automated checks can refresh objective facts; failed checks never erase the validated catalogue.</p></div>
        </div>
      </section>
      <footer className="footer"><span>THE ANALYST INDEX / PRIVATE RELEASE CANDIDATE</span><span>Evidence before endorsement.</span></footer>
      {selected && <Detail tool={selected} onClose={() => setSelected(null)} />}
    </main>
  );
}

function Detail({ tool, onClose }: { tool: Tool; onClose: () => void }) {
  useEffect(() => { const close = (event: KeyboardEvent) => event.key === "Escape" && onClose(); window.addEventListener("keydown", close); return () => window.removeEventListener("keydown", close); }, [onClose]);
  return <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.currentTarget === event.target && onClose()}><section className="detail-panel" role="dialog" aria-modal="true" aria-labelledby="detail-title"><button className="modal-close" type="button" onClick={onClose} aria-label="Close details">×</button><p className="tool-type">{tool.category}</p><h2 id="detail-title">{tool.name}</h2><p className="detail-summary">{tool.summary}</p><div className="detail-grid"><Signal label="Interaction" value={tool.interaction} /><Signal label="Data path" value={tool.data} /><Signal label="Setup" value={tool.setup} /><Signal label="Delivery" value={tool.delivery} /><Signal label="Platforms" value={tool.platforms.join(", ")} /><Signal label="Typical output" value={tool.output} /></div><div className="boundary"><b>Know before use</b><p>{tool.limitation}</p></div><div className="evidence-block"><b>Evidence record</b><p>{tool.evidence}. Last editorial review: {tool.reviewed}. Re-check upstream documentation before operational use.</p></div><a className="primary-link" href={tool.repo} target="_blank" rel="noreferrer">Open upstream repository ↗</a></section></div>;
}

function Comparison({ tools: compared, onOpen }: { tools: Tool[]; onOpen: (tool: Tool) => void }) {
  return <div className="comparison" role="region" aria-label="Side-by-side comparison"><div className="comparison-row comparison-head"><b>Decision point</b>{compared.map((tool) => <button type="button" key={tool.name} onClick={() => onOpen(tool)}>{tool.name}</button>)}</div>{[["Interaction", "interaction"], ["Data path", "data"], ["Setup", "setup"], ["Output", "output"]].map(([label, key]) => <div className="comparison-row" key={key}><b>{label}</b>{compared.map((tool) => <span key={tool.name}>{String(tool[key as keyof Tool])}</span>)}</div>)}</div>;
}

function Filter({ label, value, options, onChange }: { label: string; value: string; options: string[]; onChange: (value: string) => void }) {
  const id = label.toLowerCase().replaceAll(" ", "-");
  return <div className="filter-group"><label htmlFor={id}>{label}</label><select id={id} value={value} onChange={(event) => onChange(event.target.value)}>{options.map((option) => <option key={option}>{option}</option>)}</select></div>;
}
function Signal({ label, value }: { label: string; value: string }) { return <div className="signal"><b>{label}</b><span>{value}</span></div>; }
