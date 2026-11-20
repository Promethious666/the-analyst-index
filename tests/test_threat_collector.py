import copy
import importlib.util
import json
from pathlib import Path
import unittest

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
    if "cveawg" in url:
        return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": {"descriptions": [{"lang": "en", "value": "Fixture"}], "references": [{"url": "https://example.org/advisory"}, {"url": "javascript:alert(1)"}]}}}
    if "/search/repositories" in url:
        return {"items": [{"full_name": "example/unreviewed", "html_url": "https://github.com/example/unreviewed"}]}
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


if __name__ == "__main__":
    unittest.main()
