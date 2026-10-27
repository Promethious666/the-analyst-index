"""Refresh public vulnerability evidence without changing reviewed assessments."""

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
from datetime import datetime, timezone, timedelta
from email.utils import parsedate_to_datetime
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "public" / "threat-tracker"
CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
USER_AGENT = "The-Analyst-Index/1.0 (+https://github.com/Promethious666/the-analyst-index)"


class SourceDeferred(Exception):
    def __init__(self, retry_at):
        self.retry_at = retry_at
        super().__init__("Source deferred after rate limit")


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
    with urlopen(Request(url, headers=headers), timeout=12) as response:
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
        for exploit in record.get("exploits", []):
            if not https_url(exploit["url"]) or not exploit.get("reviewStatus"):
                raise ValueError("An exploit assessment requires provenance and review status")
            if exploit.get("commitSha") and not re.fullmatch(r"[a-f0-9]{40}", exploit["commitSha"]):
                raise ValueError("A reviewed code revision must be a full commit SHA")
        for control in record.get("controls", []):
            if not control.get("paths") or not control.get("validation") or not control.get("sourceUrls") or not all(https_url(u) for u in control["sourceUrls"]):
                raise ValueError("A control requires attack paths, validation status and sources")
        if record.get("iocs") and not all(i.get("context") and https_url(i.get("source")) for i in record["iocs"]):
            raise ValueError("An indicator requires context and a source")
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
        "published": metadata.get("datePublished"),
        "updated": metadata.get("dateUpdated"),
        "description": next((d["value"] for d in cna.get("descriptions", []) if d.get("lang", "").startswith("en")), "Not published"),
        "affected": cna.get("affected", []),
        "references": references[:60],
    }


def merge_leads(old, new, now):
    previous = {x["url"].rstrip("/").lower(): x for x in old}
    combined = {}
    for lead in new:
        if not https_url(lead.get("url", "")):
            continue
        key = lead["url"].rstrip("/").lower()
        prior = previous.get(key, {})
        current = combined.get(key, {})
        discovery = sorted(set(prior.get("discoverySources", []) + current.get("discoverySources", []) + lead.get("discoverySources", [lead["kind"]])))
        combined[key] = {**prior, **current, **lead, "repositoryUpdatedAt":max(current.get("repositoryUpdatedAt") or "",lead.get("repositoryUpdatedAt") or ""), "firstSeen": prior.get("firstSeen", now), "lastSeen": max(current.get("lastSeen", ""), lead.get("lastSeen", prior.get("lastSeen", now))), "discoverySources": discovery, "reviewStatus": "Unreviewed", "active": True}
    for key, prior in previous.items():
        if key not in combined:
            combined[key] = {**prior, "active": False}
    return sorted(combined.values(), key=lambda x: (x["active"], x.get("firstSeen", ""), x["url"]), reverse=True)[:250]


def parse_upstream_timeline(value, record_id, previous, now):
    if not isinstance(value, dict) or not isinstance(value.get("data"), list) or value.get("metadata", {}).get("vulnerability") != record_id:
        raise ValueError("Invalid upstream timeline")
    old = {x["id"]: x for x in previous if x.get("id")}
    events = {}
    for item in value["data"]:
        at = item.get("timestamp")
        try:
            datetime.fromisoformat(at.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            continue
        identity = digest([record_id, item.get("uuid"), item.get("source"), item.get("record"), item.get("field"), item.get("value"), item.get("label")])
        url = item.get("url")
        if not https_url(url):
            url = f"https://vulnerability.circl.lu/vuln/{record_id}"
        events[identity] = {"id": identity, "at": at[:10] if item.get("date_only") else at, "firstSeen": old.get(identity, {}).get("firstSeen", now), "kind": "upstream-report", "title": str(item.get("label", "Upstream dated report"))[:180], "detail": str(item.get("content") or "Date supplied by an upstream record; its significance needs review.")[:1500], "url": url, "reviewStatus": "Needs review", "sourceField": " / ".join(str(item.get(k) or "not supplied") for k in ("source", "record", "field"))}
    ordered = sorted(events.values(), key=lambda x: x["at"], reverse=True)
    return ordered[:500], f"CIRCL returned {len(value['data'])} dated reports; {min(len(ordered),500)} retained. Upstream reports are not verified disclosures or exploitation findings."


def retry_time(error, now):
    if not isinstance(error, HTTPError) or error.code not in (429, 503):
        return None
    value = error.headers.get("Retry-After", "") if error.headers else ""
    moment = datetime.fromisoformat(now.replace("Z", "+00:00"))
    try:
        result = moment + timedelta(seconds=max(0, int(value)))
    except ValueError:
        try:
            result = parsedate_to_datetime(value)
        except (ValueError, TypeError):
            result = moment + timedelta(minutes=5)
    return result.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def revision(record):
    editorial = {k: v for k, v in record.items() if k not in ("live", "history", "revision")}
    editorial["history"] = [{k:v for k,v in e.items() if k != "firstSeen"} for e in record.get("history", []) if e.get("reviewStatus") != "Needs review" and e.get("title") not in ("Evidence snapshot changed", "Reviewed technical brief changed", "Published technical brief changed", "Monitored vendor page changed")]
    live = record.get("live", {})
    substantive = {"cve": live.get("cve"), "kev": bool(live.get("kev", {}).get("listed")), "leads": sorted((x["url"],x.get("active",True),x.get("repositoryUpdatedAt")) for x in live.get("leads", [])), "timeline": [{k:v for k,v in e.items() if k != "firstSeen"} for e in live.get("timeline", [])], "vendorPageHashes": live.get("vendorPageHashes", {}), "reviewedRepositories": {k:v.get("headSha") for k,v in live.get("reviewedRepositories",{}).items()}}
    return digest({"brief": editorial, "evidence": substantive})


def collect(briefs, previous=None, offline=False, fetch=request, now=None):
    now = now or timestamp()
    ids = validate_briefs(briefs)
    previous = previous or {}
    old_records = {x["id"]: x for x in previous.get("records", [])}
    old_health = {x["name"]: x for x in previous.get("health", [])}
    deferred_hosts = {}
    upstream_fetch = fetch
    def fetch(url, **kwargs):
        host = urlparse(url).hostname
        if deferred_hosts.get(host, "") > now:
            raise SourceDeferred(deferred_hosts[host])
        try:
            return upstream_fetch(url, **kwargs)
        except HTTPError as error:
            until = retry_time(error, now)
            if until:
                deferred_hosts[host] = until
            raise
    output = {"schemaVersion": 1, "generatedAt": now, "records": [], "health": [], "candidates": copy.deepcopy(previous.get("candidates", []))}
    candidates = {x["id"]: x for x in output["candidates"] if x.get("id") not in ids}
    records = output["records"]
    for brief in briefs["records"]:
        record = copy.deepcopy(brief)
        prior = old_records.get(record["id"], {})
        record["live"] = copy.deepcopy(prior.get("live", {}))
        prior_events = {(x["at"], x["title"]): x for x in prior.get("history", [])}
        combined = copy.deepcopy([*prior.get("history", []), *record["history"]])
        record["history"] = sorted({(x["at"], x["title"]): {**x,"firstSeen":prior_events.get((x["at"],x["title"]),{}).get("firstSeen",now)} for x in combined}.values(), key=lambda x: x["at"])
        records.append(record)

    def check(name, work):
        prior = old_health.get(name, {})
        status = {"name": name, "status": "pending" if offline else "ok", "checkedAt": None if offline else now, "lastSuccess": prior.get("lastSuccess")}
        output["health"].append(status)
        if offline:
            return None
        if prior.get("retryAt", "") > now:
            status.update(status="error", error="Source deferred until Retry-After expires; previous evidence retained", retryAt=prior["retryAt"])
            return None
        try:
            result = work()
            status["lastSuccess"] = now
            return result
        except Exception as error:
            status["status"] = "error"
            if isinstance(error, HTTPError):
                status["error"] = f"HTTP {error.code}; last successful evidence retained"
                until = retry_time(error, now)
                if until:
                    status["retryAt"] = until
            else:
                status["error"] = f"{type(error).__name__}; last successful evidence retained"
                if isinstance(error, SourceDeferred):
                    status["retryAt"] = error.retry_at
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

    reviewed_heads = {}
    reviewed_repos = {e["repositoryUrl"] for record in records for e in record.get("exploits",[]) if e.get("commitSha") and re.fullmatch(r"https://github.com/[\w.-]+/[\w.-]+",e.get("repositoryUrl",""))}
    for repository_url in sorted(reviewed_repos):
        full_name = urlparse(repository_url).path.strip("/")
        def latest_revision(full_name=full_name):
            value = fetch(f"https://api.github.com/repos/{full_name}/commits?per_page=1")
            if not isinstance(value,list) or not value or not re.fullmatch(r"[a-f0-9]{40}",value[0].get("sha","")):
                raise ValueError("Invalid repository revision response")
            return value[0]["sha"]
        reviewed_heads[repository_url] = check(f"Reviewed repository: {full_name}",latest_revision)

    for record in records:
        record_id, live = record["id"], record["live"]
        for exploit in record.get("exploits",[]):
            repo_url = exploit.get("repositoryUrl")
            head = reviewed_heads.get(repo_url)
            if head:
                live.setdefault("reviewedRepositories",{})[repo_url] = {"reviewedSha":exploit["commitSha"],"headSha":head,"checkedAt":now,"reviewedAt":exploit["reviewedAt"]}
        value = check(f"CVE record: {record_id}", lambda record_id=record_id: cve_record(fetch(f"https://cveawg.mitre.org/api/cve/{record_id}")))
        if value is not None:
            live["cve"] = value
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
        query = urlencode({"q": f'"{record_id}" in:name,description,readme', "per_page": 20, "sort": "updated"})
        def repository_leads(query=query):
            value = fetch("https://api.github.com/search/repositories?" + query)
            if not isinstance(value,dict) or not isinstance(value.get("items"),list) or not all(isinstance(x,dict) for x in value["items"]):
                raise ValueError("Invalid repository search response")
            return value
        repositories = check(f"Repository leads: {record_id}",repository_leads)
        old_leads = live.get("leads", [])
        lead_sources = live.setdefault("leadSources", {})
        if not lead_sources:
            for lead in old_leads:
                lead_sources.setdefault(lead["kind"], []).append(lead)
        if repositories is not None:
            lead_sources["Repository mention"] = [{"title": x.get("full_name", "Repository mention"), "url": x.get("html_url", ""), "description": str(x.get("description") or "")[:500], "repositoryCreatedAt": x.get("created_at"), "repositoryUpdatedAt":x.get("pushed_at"), "kind": "Repository mention", "discoverySources": ["GitHub search"], "lastSeen": now} for x in repositories.get("items", [])]
        index_url = f"https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{record_id.split('-')[1]}/{record_id}.json"
        def index_leads():
            value = fetch(index_url, limit=2_000_000)
            if not isinstance(value, list) or not all(isinstance(x, dict) and isinstance(x.get("html_url"), str) for x in value):
                raise ValueError("Invalid PoC index response")
            return {"items":[{"title": x.get("full_name", "PoC index mention"), "url": x["html_url"], "description": str(x.get("description") or "")[:500], "repositoryCreatedAt": x.get("created_at"), "repositoryUpdatedAt":x.get("pushed_at"), "kind": "Repository mention", "discoverySources": ["PoC-in-GitHub"], "lastSeen": now} for x in value[:200]],"total":len(value)}
        indexed = check(f"PoC index: {record_id}", index_leads)
        if indexed is not None:
            lead_sources["PoC index"] = indexed["items"]
            live["indexCoverage"] = f"PoC-in-GitHub supplied {indexed['total']} entries; {len(indexed['items'])} collected under the per-source limit."
        for repo, kind in [("projectdiscovery/nuclei-templates", "Nuclei template reference"), ("SigmaHQ/sigma", "Sigma rule reference")]:
            if next((x["status"] for x in output["health"] if x["name"] == repo), None) == "ok":
                lead_sources[kind] = [{**x,"lastSeen":now} for x in template_matches[record_id] if x["kind"] == kind]
        leads = [x for values in lead_sources.values() for x in values]
        live["leads"] = merge_leads(old_leads, leads, now)
        live["leadCoverage"] = f"{len(set(x['url'].rstrip('/').lower() for x in leads))} distinct links returned by the retained source snapshots. Up to 250 active and historical links are kept. Search and filename matches are not exhaustive. " + live.get("indexCoverage", "")
        def upstream_timeline():
            value = fetch(f"https://vulnerability.circl.lu/api/vulnerability/{record_id}/timeline", limit=8_000_000)
            return parse_upstream_timeline(value, record_id, live.get("timeline", []), now)
        timeline = check(f"CIRCL timeline: {record_id}", upstream_timeline)
        if timeline is not None:
            live["timeline"], live["timelineCoverage"] = timeline
            for event in live["timeline"]:
                for candidate_id in {x.upper() for x in CVE_PATTERN.findall(event["title"]+" "+event["detail"]+" "+event["sourceField"])}-ids:
                    candidate_id = candidate_id.upper()
                    item = candidates.setdefault(candidate_id,{"id":candidate_id,"product":record["product"],"url":event["url"],"firstSeen":now,"relationship":"Co-mentioned in an upstream report; unreviewed","relatedTo":[]})
                    item["relatedTo"] = sorted(set(item.get("relatedTo",[])+[record_id]))

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
            if record["id"] in monitor.get("recordIds",[]) or (not monitor.get("recordIds") and record["product"] == monitor["product"]):
                old_hash = old_records.get(record["id"], {}).get("live", {}).get("vendorPageHashes",{}).get(monitor["url"])
                record["live"].setdefault("vendorPageHashes",{})[monitor["url"]] = content_hash
                if old_hash and old_hash != content_hash:
                    record["history"].append({"at": now,"firstSeen":now,"kind":"source-update","reviewStatus":"Needs review", "title": "Monitored vendor page changed", "detail": "Content changed; technical implications require review. This does not establish a new vulnerability or changed mitigation.", "url": monitor["url"]})

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
            old_urls = {x["url"] for x in earlier.get("leads", []) if x.get("active",True)}
            new_urls = {x["url"] for x in current.get("leads", []) if x.get("active",True)}
            if new_urls - old_urls:
                changes.append(f"{len(new_urls - old_urls)} new unreviewed research links")
            if old_urls - new_urls:
                changes.append(f"{len(old_urls - new_urls)} links no longer returned by the source")
            if [{k:v for k,v in e.items() if k != "firstSeen"} for e in earlier.get("timeline", [])] != [{k:v for k,v in e.items() if k != "firstSeen"} for e in current.get("timeline", [])]:
                changes.append("Upstream dated reports changed; their meaning needs review")
            if {k:v.get("headSha") for k,v in earlier.get("reviewedRepositories",{}).items()} != {k:v.get("headSha") for k,v in current.get("reviewedRepositories",{}).items()}:
                changes.append("A reviewed repository has a different current revision; compare it with the pinned review")
            if changes:
                record["history"].append({"at": now,"firstSeen":now,"kind":"source-update","reviewStatus":"Needs review", "title": "Evidence snapshot changed", "detail": "; ".join(changes) + ". Automatic additions remain unreviewed."})
            elif earlier.get("vendorPageHashes") == current.get("vendorPageHashes"):
                record["history"].append({"at": now,"firstSeen":now,"kind":"assessment-update","reviewStatus":"Needs review", "title": "Published technical brief changed", "detail": "The published assessment or evidence changed; inspect the current brief and sources."})
        reviewed_events = [e for e in record["history"] if e.get("reviewStatus") != "Needs review" and e.get("title") not in ("Evidence snapshot changed","Reviewed technical brief changed","Published technical brief changed","Monitored vendor page changed")]
        automatic_events = [e for e in record["history"] if e not in reviewed_events]
        record["history"] = sorted([*reviewed_events,*automatic_events[-100:]],key=lambda e:e["at"])
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
    for source in output["health"]:
        if source["status"] == "error":
            print(f"Source unavailable: {source['name']} ({source['error']})")


if __name__ == "__main__":
    main()
