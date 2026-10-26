"""Refresh public vulnerability evidence without changing reviewed assessments."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "public" / "threat-tracker"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
USER_AGENT = "The-Analyst-Index/1.0 (+https://github.com/Promethious666/the-analyst-index)"


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def https_url(value):
    try:
        parsed = urlparse(value)
        return parsed.scheme == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password
    except (ValueError, TypeError, AttributeError):
        return False


def request(url, *, expect_json=True, limit=12_000_000):
    if not https_url(url):
        raise ValueError("Only public HTTPS source URLs are supported")
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json" if expect_json else "text/html"}
    if urlparse(url).hostname == "api.github.com" and os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    with urlopen(Request(url, headers=headers), timeout=25) as response:
        if headers.get("Authorization") and urlparse(response.url).hostname != "api.github.com":
            raise ValueError("Unexpected authenticated-source redirect")
        payload = response.read(limit + 1)
        if len(payload) > limit:
            raise ValueError("Source response exceeded the collection limit")
    text = payload.decode("utf-8")
    return json.loads(text) if expect_json else text


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()[:20]


def validate_briefs(briefs):
    ids = set()
    for record in briefs["records"]:
        if not re.fullmatch(r"CVE-\d{4}-\d{4,}", record["id"]) or record["id"] in ids:
            raise ValueError("Invalid or duplicate tracked CVE")
        ids.add(record["id"])
        if not record["sources"]:
            raise ValueError("Every reviewed brief requires a source")
        for source in record["sources"]:
            if not https_url(source["url"]):
                raise ValueError("Invalid reviewed source URL")
        for relation in record["related"]:
            if not https_url(relation["source"]):
                raise ValueError("A relationship requires an HTTPS evidence source")
    return ids


def cve_record(value):
    metadata = value.get("cveMetadata", {})
    containers = value.get("containers", {})
    cna = containers.get("cna", {})
    references = []
    for container in [cna, *containers.get("adp", [])]:
        for reference in container.get("references", []):
            url = reference.get("url", "")
            if https_url(url) and url not in references:
                references.append(url)
    return {
        "state": metadata.get("state", "Not established"),
        "updated": metadata.get("dateUpdated"),
        "description": next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "Not published"),
        "affected": cna.get("affected", []),
        "references": references[:60],
    }


def merge_leads(old, new, now):
    previous = {x["url"]: x for x in old}
    combined = []
    for lead in new:
        if not https_url(lead.get("url", "")):
            continue
        combined.append({**lead, "firstSeen": previous.get(lead["url"], {}).get("firstSeen", now), "reviewStatus": "Unreviewed"})
    return sorted({x["url"]: x for x in combined}.values(), key=lambda x: x["url"])[:60]


def revision(record):
    editorial = {k: v for k, v in record.items() if k not in ("live", "history", "revision")}
    live = record.get("live", {})
    substantive = {"cve": live.get("cve"), "kev": bool(live.get("kev", {}).get("listed")), "leads": sorted(x["url"] for x in live.get("leads", [])), "vendorPageHash": live.get("vendorPageHash")}
    return digest({"brief": editorial, "evidence": substantive})


def collect(briefs, previous=None, offline=False, fetch=request, now=None):
    now = now or timestamp()
    ids = validate_briefs(briefs)
    previous = previous or {}
    old_records = {x["id"]: x for x in previous.get("records", [])}
    old_health = {x["name"]: x for x in previous.get("health", [])}
    output = {"schemaVersion": 1, "generatedAt": now, "records": [], "health": [], "candidates": copy.deepcopy(previous.get("candidates", []))}
    candidates = {x["id"]: x for x in output["candidates"] if x.get("id") not in ids}
    records = output["records"]
    for brief in briefs["records"]:
        record = copy.deepcopy(brief)
        prior = old_records.get(record["id"], {})
        record["live"] = copy.deepcopy(prior.get("live", {}))
        combined = copy.deepcopy([*record["history"], *prior.get("history", [])])
        record["history"] = sorted({(x["at"], x["title"]): x for x in combined}.values(), key=lambda x: x["at"])
        records.append(record)

    def check(name, work):
        prior = old_health.get(name, {})
        status = {"name": name, "status": "pending" if offline else "ok", "checkedAt": None if offline else now, "lastSuccess": prior.get("lastSuccess")}
        output["health"].append(status)
        if offline:
            return None
        try:
            result = work()
            status["lastSuccess"] = now
            return result
        except Exception as error:
            status["status"] = "error"
            if isinstance(error, HTTPError):
                status["error"] = f"HTTP {error.code}; last successful evidence retained"
            else:
                status["error"] = f"{type(error).__name__}; last successful evidence retained"
            return None

    def load_kev():
        value = fetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        if not isinstance(value.get("vulnerabilities"), list):
            raise ValueError("Invalid KEV response")
        return {x["cveID"]: x for x in value["vulnerabilities"]}

    kev = check("CISA KEV", load_kev)
    def load_epss():
        value = fetch("https://api.first.org/data/v1/epss?" + urlencode({"cve": ",".join(sorted(ids))}))
        if not isinstance(value.get("data"), list):
            raise ValueError("Invalid EPSS response")
        for item in value["data"]:
            if not 0 <= float(item["epss"]) <= 1 or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", item["date"]):
                raise ValueError("Invalid EPSS probability or score date")
        return value
    epss = check("FIRST EPSS", load_epss)
    epss_by_id = {x["cve"]: x for x in (epss or {}).get("data", [])}
    template_matches = {record_id: [] for record_id in ids}
    for repo, branch, kind in [("projectdiscovery/nuclei-templates", "main", "Nuclei template reference"), ("SigmaHQ/sigma", "master", "Sigma rule reference")]:
        def templates(repo=repo, branch=branch, kind=kind):
            value = fetch(f"https://api.github.com/repos/{repo}/git/trees/{branch}?recursive=1")
            if value.get("truncated") or not isinstance(value.get("tree"), list):
                raise ValueError("Incomplete template tree")
            for item in value["tree"]:
                path = item.get("path", "")
                for record_id in ids:
                    if record_id.lower() in path.lower() and item.get("type") == "blob":
                        template_matches[record_id].append({"title": path, "url": f"https://github.com/{repo}/blob/{branch}/{quote(path, safe='/')}", "kind": kind})
            return True
        check(repo, templates)

    for record in records:
        record_id, live = record["id"], record["live"]
        value = check(f"CVE record: {record_id}", lambda record_id=record_id: fetch(f"https://cveawg.mitre.org/api/cve/{record_id}"))
        if value is not None:
            live["cve"] = cve_record(value)
            live["references"] = live["cve"]["references"]
            live["cveCheckedAt"] = now
        if kev is not None:
            live["kev"] = {"listed": record_id in kev, "checkedAt": now, "dateAdded": kev.get(record_id, {}).get("dateAdded")}
        if record_id in epss_by_id:
            item = epss_by_id[record_id]
            score = float(item["epss"])
            if not 0 <= score <= 1:
                raise ValueError("Invalid EPSS probability")
            live["epss"] = {"score": score, "date": item["date"], "checkedAt": now}
        query = urlencode({"q": f'"{record_id}" in:name,description,readme', "per_page": 5, "sort": "updated"})
        repositories = check(f"Repository leads: {record_id}", lambda query=query: fetch("https://api.github.com/search/repositories?" + query))
        old_leads = live.get("leads", [])
        leads = list(old_leads)
        if repositories is not None:
            leads = [x for x in leads if x["kind"] != "Repository mention"]
            leads += [{"title": x.get("full_name", "Repository mention"), "url": x.get("html_url", ""), "kind": "Repository mention"} for x in repositories.get("items", [])]
        for repo, kind in [("projectdiscovery/nuclei-templates", "Nuclei template reference"), ("SigmaHQ/sigma", "Sigma rule reference")]:
            if next((x["status"] for x in output["health"] if x["name"] == repo), None) == "ok":
                leads = [x for x in leads if x["kind"] != kind]
                leads += [x for x in template_matches[record_id] if x["kind"] == kind]
        live["leads"] = merge_leads(old_leads, leads, now)

    for monitor in briefs.get("monitors", []):
        page = check(monitor["name"], lambda monitor=monitor: fetch(monitor["url"], expect_json=False))
        if page is None:
            continue
        found = sorted(set(x.upper() for x in CVE_PATTERN.findall(page)))
        for candidate_id in found:
            if candidate_id not in ids and candidate_id not in candidates:
                candidates[candidate_id] = {"id": candidate_id, "product": monitor["product"], "url": monitor["url"], "firstSeen": now, "relationship": "Shared monitored source; unreviewed"}
        # A changed vendor page needs review even if no new CVE identifier appears.
        content_hash = digest(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", page)).strip())
        for record in records:
            if record["product"] == monitor["product"]:
                old_hash = old_records.get(record["id"], {}).get("live", {}).get("vendorPageHash")
                record["live"]["vendorPageHash"] = content_hash
                if old_hash and old_hash != content_hash:
                    record["history"].append({"at": now, "title": "Monitored vendor page changed", "detail": "Content changed; technical implications require review. This does not establish a new vulnerability or changed mitigation.", "url": monitor["url"]})

    for record in records:
        prior = old_records.get(record["id"], {})
        record["revision"] = revision(record)
        if prior.get("revision") and prior["revision"] != record["revision"]:
            earlier, current = prior.get("live", {}), record["live"]
            changes = []
            if earlier.get("cve") != current.get("cve"):
                changes.append("CVE record content changed")
            if earlier.get("kev", {}).get("listed") != current.get("kev", {}).get("listed"):
                changes.append("CISA KEV status: " + ("listed" if current.get("kev", {}).get("listed") else "not listed in the retrieved catalogue"))
            old_urls = {x["url"] for x in earlier.get("leads", [])}
            new_urls = {x["url"] for x in current.get("leads", [])}
            if new_urls - old_urls:
                changes.append(f"{len(new_urls - old_urls)} new unreviewed research links")
            if old_urls - new_urls:
                changes.append(f"{len(old_urls - new_urls)} links no longer returned by the source")
            if changes:
                record["history"].append({"at": now, "title": "Evidence snapshot changed", "detail": "; ".join(changes) + ". Automatic additions remain unreviewed."})
            elif earlier.get("vendorPageHash") == current.get("vendorPageHash"):
                record["history"].append({"at": now, "title": "Reviewed technical brief changed", "detail": "The published technical assessment was updated; inspect the current brief and sources."})
        record["history"] = record["history"][-100:]
    output["candidates"] = sorted(candidates.values(), key=lambda x: (x["firstSeen"], x["id"]), reverse=True)[:150]
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true", help="Prepare the reviewed starting snapshot without external collection")
    parser.add_argument("--previous-url", help="Read the last deployed snapshot to preserve history between deployments")
    args = parser.parse_args()
    briefs = json.loads((SOURCE / "briefs.json").read_text(encoding="utf-8"))
    data_path = SOURCE / "data.json"
    previous = json.loads(data_path.read_text(encoding="utf-8")) if data_path.exists() else None
    if args.previous_url:
        expected = "https://promethious666.github.io/the-analyst-index/threat-tracker/data.json"
        if args.previous_url != expected:
            parser.error("Previous snapshot must come from the configured public tracker URL")
        try:
            deployed = request(args.previous_url)
            if deployed.get("schemaVersion") != 1 or not isinstance(deployed.get("records"), list):
                raise ValueError("Invalid previous snapshot")
            previous = deployed
        except Exception:
            print("Previous deployment unavailable; using the checked-in snapshot.")
    output = collect(briefs, previous, offline=args.offline)
    data_path.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    target = ROOT / "docs" / "threat-tracker"
    target.mkdir(parents=True, exist_ok=True)
    for path in SOURCE.iterdir():
        if path.is_file():
            shutil.copy2(path, target / path.name)
    failed = sum(x["status"] == "error" for x in output["health"])
    print(f"Prepared {len(output['records'])} briefs, {len(output['candidates'])} review candidates; {failed} source checks failed.")


if __name__ == "__main__":
    main()
