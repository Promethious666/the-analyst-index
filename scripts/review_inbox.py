"""Group public defensive bulletins by a shared identifier and retain material changes."""
import hashlib
import json
import re
from datetime import date, timedelta
from html.parser import HTMLParser
from urllib.parse import urlencode


class ArticleText(HTMLParser):
    """Prefer article content and ignore scripts, styles and navigation."""
    ignored = {"script", "style", "nav", "footer", "noscript", "svg"}

    def __init__(self):
        super().__init__()
        self.skip = 0
        self.main = 0
        self.all_text = []
        self.main_text = []

    def handle_starttag(self, tag, attrs):
        self.skip += tag in self.ignored
        self.main += tag in {"main", "article"}

    def handle_endtag(self, tag):
        if tag in self.ignored:
            self.skip = max(0, self.skip - 1)
        if tag in {"main", "article"}:
            self.main = max(0, self.main - 1)

    def handle_data(self, data):
        if not self.skip:
            self.all_text.append(data)
            if self.main:
                self.main_text.append(data)


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:24]


def article_hash(page):
    parser = ArticleText()
    parser.feed(page)
    text = " ".join(" ".join(parser.main_text).split())
    if len(text) < 100:
        text = " ".join(" ".join(parser.all_text).split())
    if len(text) < 100:
        raise ValueError("No article text")
    return fingerprint(text)


def github_reports(fetch, feed, cutoff):
    params = {"type": feed, "sort": "updated", "direction": "desc", "per_page": 50,
              "modified": ">=" + cutoff}
    if feed == "reviewed":
        params["severity"] = "critical"
    rows = fetch("https://api.github.com/advisories?" + urlencode(params))
    if not isinstance(rows, list):
        raise ValueError("Invalid advisory response")
    reports = []
    for row in rows:
        ghsa = row["ghsa_id"]
        if not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa, re.I):
            raise ValueError("Invalid advisory identifier")
        cve = row.get("cve_id") or ""
        key = cve.upper() if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.I) else ghsa
        versions = []
        for item in row.get("vulnerabilities") or []:
            package = (item.get("package") or {}).get("name")
            if package:
                fixed = item.get("first_patched_version")
                versions.append(f"{package}: {item.get('vulnerable_version_range') or 'range unspecified'}"
                                + (f" (fixed in {fixed})" if fixed else ""))
        report = {"publisher": "GitHub Advisory Database", "date": row["updated_at"],
                  "summary": row.get("summary") or ghsa, "versions": sorted(set(versions)),
                  "url": "https://github.com/advisories/" + ghsa}
        if row.get("withdrawn_at"):
            report["status"] = "Withdrawn by publisher"
        reports.append((key, "Malicious package" if feed == "malware" else "Vulnerability", report))
    return reports


def collect_inbox(briefs, records, previous, kev, check, fetch, now):
    cutoff = (date.fromisoformat(now[:10]) - timedelta(days=30)).isoformat()
    old = {item["id"]: item for item in previous}
    items = {}
    def case(key, title, kind, summary=""):
        return items.setdefault(key, {"id": key, "title": title, "kind": kind, "summary": summary,
                                      "reports": {}, "history": [], "brief": False})

    for watched in briefs.get("watchCases", []):
        item = case(watched["id"], watched["title"], watched["kind"], watched["summary"])
        for source in watched["reports"]:
            url = source["url"]
            prior = old.get(item["id"], {}).get("reports", {}).get(url, {})
            current = check("Review page: " + item["id"] + " / " + source["publisher"],
                            lambda url=url: article_hash(fetch(url, expect_json=False, limit=6_000_000)))
            report = dict(source)
            if current or prior.get("pageHash"):
                report["pageHash"] = current or prior["pageHash"]
            item["reports"][url] = report

    for record in records:
        item = case(record["id"], record["title"], "Vulnerability", record["summary"])
        item["brief"] = True
        for event in record.get("history", []):
            if event.get("url") and event.get("reviewStatus") == "Source reviewed":
                url = event["url"]
                item["reports"][url] = {"publisher": next((s["publisher"] for s in record["sources"]
                    if s["url"] == url), "Reviewed source"), "date": event["at"], "url": url,
                    "summary": event.get("detail") or event["title"]}
        if record.get("sources") and not item["reports"]:
            s = record["sources"][0]
            item["reports"][s["url"]] = {"publisher": s["publisher"], "date": record["reviewedAt"],
                                         "summary": record["summary"], "url": s["url"]}
        item["briefRevision"] = record["revision"]
        item["briefChange"] = next((e.get("detail") or e["title"] for e in reversed(record.get("history", []))
                                    if e.get("reviewStatus") == "Needs review"), "")

    # Keep recent bulletins through feed outages and rolling result windows.
    for key, prior in old.items():
        for url, report in prior["reports"].items():
            if report.get("feed") and (report["date"][:10] >= cutoff or key in items):
                case(key, prior["title"], prior["kind"])["reports"].setdefault(url, report)

    if kev is not None:
        for key, entry in kev.items():
            if not re.fullmatch(r"CVE-\d{4}-\d{4,}", key) or (entry.get("dateAdded","") < cutoff and key not in items):
                continue
            title = entry.get("vulnerabilityName") or key
            url = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search=" + key
            case(key, title, "Vulnerability")["reports"][url] = {
                "publisher": "CISA KEV", "date": entry["dateAdded"], "url": url, "feed": "kev",
                "summary": entry.get("shortDescription") or title, "status": "CISA lists known exploitation",
                "action": entry.get("requiredAction") or ""}
        for key, item in items.items():
            for url, report in list(item["reports"].items()):
                if report.get("feed") == "kev" and key not in kev:
                    item["reports"][url] = {**report, "status":"Removed from retrieved CISA catalogue"}

    for feed in ("reviewed", "malware"):
        rows = check("GitHub advisories: " + feed, lambda feed=feed: github_reports(fetch, feed, cutoff))
        for key, kind, report in rows or []:
            ghsa = report["url"].rsplit("/", 1)[-1]
            if ghsa != key and ghsa in items:
                displaced = items.pop(ghsa)
                target = case(key, report["summary"], kind)
                target["reports"].update(displaced["reports"])
                earlier = old.pop(ghsa, {})
                if earlier:
                    combined = dict(old.get(key, {}))
                    combined["reports"] = {**earlier.get("reports", {}), **combined.get("reports", {})}
                    combined["history"] = [*earlier.get("history", []), *combined.get("history", [])]
                    old[key] = combined
            case(key, report["summary"], kind)["reports"][report["url"]] = {**report, "feed": feed}

    for key, item in items.items():
        prior = old.get(key, {})
        events = list(prior.get("history", []))
        for url, report in item["reports"].items():
            before = prior.get("reports", {}).get(url)
            changes = []
            if before is None:
                changes.append(report["summary"])
            else:
                for field, label in (("summary","Advisory"), ("versions","Affected / fixed versions"),
                                     ("action","Recommended action"), ("status","Publisher status")):
                    if before.get(field) != report.get(field):
                        value = report.get(field)
                        value = ", ".join(value) if isinstance(value,list) else value
                        changes.append(f"{label}: {value or 'removed by source'}")
                if before.get("pageHash") and report.get("pageHash") != before["pageHash"]:
                    changes.append("Source page text changed. Its technical meaning needs review.")
            if changes:
                events.append({"at": now, "date": report["date"], "source": report["publisher"],
                               "url": url, "text": " ".join(changes)})
        if prior.get("briefRevision") and prior["briefRevision"] != item.get("briefRevision") and item["brief"]:
            events.append({"at":now, "date":now, "source":"Technical brief", "url":"",
                           "text":item["briefChange"] or "The technical brief was revised."})
        item["history"] = sorted(events, key=lambda e:(e["at"],e["date"],e["source"]))[-60:]
        item["revision"] = fingerprint([(e["at"],e["text"],e["url"]) for e in item["history"]])
        item["latest"] = max((r["date"] for r in item["reports"].values()), default="")
    return sorted(items.values(), key=lambda i:(i["latest"],i["id"]), reverse=True)


def inbox_json(data):
    inbox_health = [h for h in data["health"] if h["name"] == "CISA KEV" or h["name"].startswith(("Review page:", "GitHub advisories:"))]
    payload = {"schemaVersion": 1, "items": data["inbox"], "generatedAt": data["generatedAt"], "health": inbox_health}
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":")).replace("<", "\\u003c")
