import copy
import importlib.util
import json
from pathlib import Path
import unittest
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("collector", ROOT / "scripts" / "collect-threats.py")
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)
BRIEFS = json.loads((ROOT / "public" / "threat-tracker" / "briefs.json").read_text(encoding="utf-8"))
NOW = "2026-10-26T12:00:00Z"


def fixture_fetch(url, **kwargs):
    if "known_exploited" in url:
        return {"vulnerabilities": [{"cveID": BRIEFS["records"][0]["id"], "dateAdded": "2026-10-26"}]}
    if "api.first.org" in url:
        return {"data": []}
    if "/git/trees/" in url:
        return {"truncated": False, "tree": []}
    if "/commits?" in url:
        return [{"sha":"a"*40}]
    if "cveawg" in url:
        return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Fixture"}], "references": [{"url": "https://example.org/advisory"}, {"url": "javascript:alert(1)"}]}}}
    if "/search/repositories" in url:
        return {"items": [{"full_name": "example/unreviewed", "html_url": "https://github.com/example/unreviewed"}]}
    if "PoC-in-GitHub" in url:
        return [{"full_name":"example/unreviewed","html_url":"https://github.com/example/unreviewed","description":"An unverified claim"}]
    if "vulnerability.circl.lu" in url:
        record_id = url.split("/")[-2]
        return {"metadata":{"vulnerability":record_id},"data":[{"timestamp":"2026-10-20T12:00:00Z","label":"Exploitation reported by a source","source":"example","record":record_id,"field":"observation.timestamp","value":"2026-10-20T12:00:00Z","kind":"sighting","uuid":"fixture","content":"Unreviewed claim","url":"https://example.org/report"}]}
    return "New advisory mentions CVE-2026-123456."


class CollectorTests(unittest.TestCase):
    def test_new_references_are_unreviewed_and_new_cves_are_quarantined(self):
        value = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        self.assertEqual(value["records"][0]["live"]["leads"][0]["reviewStatus"], "Unreviewed")
        self.assertEqual(value["candidates"][0]["id"], "CVE-2026-123456")
        self.assertNotIn("CVE-2026-123456", [x["id"] for x in value["records"]])
        self.assertEqual(value["records"][0]["summary"], BRIEFS["records"][0]["summary"])
        self.assertEqual(value["records"][0]["live"]["references"], ["https://example.org/advisory"])

    def test_failed_refresh_retains_last_success_and_evidence(self):
        before = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        def fail(url, **kwargs):
            raise TimeoutError("Fixture outage")
        after = collector.collect(BRIEFS, previous=before, fetch=fail, now="2026-10-26T16:00:00Z")
        self.assertTrue(all(x["status"] == "error" for x in after["health"]))
        self.assertTrue(all(x["lastSuccess"] == NOW for x in after["health"]))
        self.assertEqual(after["records"][0]["live"]["kev"], before["records"][0]["live"]["kev"])
        self.assertEqual(after["records"][0]["live"]["leads"], before["records"][0]["live"]["leads"])

    def test_refresh_timestamps_do_not_create_false_evidence_changes(self):
        before = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        after = collector.collect(BRIEFS, previous=before, fetch=fixture_fetch, now="2026-10-26T16:00:00Z")
        self.assertEqual(after["records"][0]["revision"], before["records"][0]["revision"])
        self.assertEqual(after["records"][0]["history"], before["records"][0]["history"])

    def test_a_new_kev_listing_changes_evidence_but_not_reviewed_assessment(self):
        before = collector.collect(BRIEFS, offline=True, now=NOW)
        after = collector.collect(BRIEFS, previous=before, fetch=fixture_fetch, now="2026-10-26T16:00:00Z")
        self.assertNotEqual(before["records"][0]["revision"], after["records"][0]["revision"])
        self.assertTrue(after["records"][0]["live"]["kev"]["listed"])
        self.assertEqual(after["records"][0]["exploitation"], before["records"][0]["exploitation"])

    def test_rejected_or_reserved_records_do_not_invent_affected_versions(self):
        parsed = collector.cve_record({"cveMetadata": {"state": "RESERVED"}})
        self.assertEqual(parsed["state"], "RESERVED")
        self.assertEqual(parsed["affected"], [])

    def test_invalid_epss_is_a_failed_source_not_a_failed_collection(self):
        def invalid(url, **kwargs):
            if "api.first.org" in url:
                return {"data": [{"cve": BRIEFS["records"][0]["id"], "epss": "99", "date": "2026-10-26"}]}
            return fixture_fetch(url, **kwargs)
        value = collector.collect(BRIEFS, fetch=invalid, now=NOW)
        self.assertEqual(next(x for x in value["health"] if x["name"] == "FIRST EPSS")["status"], "error")
        self.assertNotIn("epss", value["records"][0]["live"])

    def test_multiple_discovery_sources_deduplicate_without_losing_provenance(self):
        value = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        leads = value["records"][0]["live"]["leads"]
        self.assertEqual(len(leads),1)
        self.assertEqual(leads[0]["discoverySources"],["GitHub search","PoC-in-GitHub"])
        after = collector.merge_leads(leads,[],"2026-10-27T12:00:00Z")
        self.assertFalse(after[0]["active"])
        self.assertEqual(after[0]["firstSeen"],NOW)

    def test_upstream_claim_never_becomes_confirmed_exploitation(self):
        value = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        record = value["records"][0]
        self.assertEqual(record["exploitation"],BRIEFS["records"][0]["exploitation"])
        event = record["live"]["timeline"][0]
        self.assertEqual(event["reviewStatus"],"Needs review")
        self.assertEqual(event["kind"],"upstream-report")
        self.assertIn("observation.timestamp",event["sourceField"])
        self.assertEqual(event["firstSeen"],NOW)

    def test_late_discovery_preserves_event_date_and_first_seen(self):
        before = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        after = collector.collect(BRIEFS, previous=before, fetch=fixture_fetch, now="2026-10-28T12:00:00Z")
        self.assertEqual(after["records"][0]["live"]["timeline"][0]["firstSeen"],NOW)
        self.assertEqual(after["records"][0]["live"]["timeline"][0]["at"],"2026-10-20T12:00:00Z")

    def test_rate_limit_defers_other_requests_and_retains_old_evidence(self):
        before = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        calls=[]
        def limited(url, **kwargs):
            if "vulnerability.circl.lu" in url:
                calls.append(url)
                raise HTTPError(url,429,"Limit",{"Retry-After":"3600"},None)
            return fixture_fetch(url,**kwargs)
        after = collector.collect(BRIEFS, previous=before, fetch=limited, now="2026-10-26T16:00:00Z")
        self.assertEqual(len(calls),1)
        statuses=[s for s in after["health"] if s["name"].startswith("CIRCL")]
        self.assertTrue(all(s["status"]=="error" and s["retryAt"]=="2026-10-26T17:00:00Z" for s in statuses))
        self.assertEqual(after["records"][0]["live"]["timeline"],before["records"][0]["live"]["timeline"])

    def test_corrections_to_reviewed_history_override_previous_text(self):
        before = collector.collect(BRIEFS, fetch=fixture_fetch, now=NOW)
        corrected = copy.deepcopy(BRIEFS)
        corrected["records"][0]["history"][0]["detail"]="Corrected source interpretation"
        after = collector.collect(corrected,previous=before,fetch=fixture_fetch,now="2026-10-27T12:00:00Z")
        self.assertEqual(after["records"][0]["history"][0]["detail"],"Corrected source interpretation")
        again = collector.collect(corrected,previous=after,fetch=fixture_fetch,now="2026-10-28T12:00:00Z")
        self.assertEqual(again["records"][0]["revision"],after["records"][0]["revision"])
        self.assertEqual(again["records"][0]["history"],after["records"][0]["history"])

    def test_reviewed_milestones_survive_the_automatic_history_limit(self):
        before = collector.collect(BRIEFS,fetch=fixture_fetch,now=NOW)
        before["records"][0]["history"].extend({"at":f"2026-10-26T12:{i//60:02d}:{i%60:02d}Z","title":f"Change {i}","reviewStatus":"Needs review","kind":"source-update"} for i in range(120))
        after = collector.collect(BRIEFS,previous=before,fetch=fixture_fetch,now="2026-10-27T12:00:00Z")
        self.assertTrue(any(e["title"]==BRIEFS["records"][0]["history"][0]["title"] for e in after["records"][0]["history"]))
        self.assertEqual(len([e for e in after["records"][0]["history"] if e.get("reviewStatus")=="Needs review"]),100)


if __name__ == "__main__":
    unittest.main()
