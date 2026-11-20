# Threat Tracker

A public vulnerability research tracker with source-backed technical briefs, local watchlists, collection health, discovery leads and report export.

## Phase one

The tracker lives at `/the-analyst-index/threat-tracker/`. Its source is in `public/threat-tracker/`; the published copy is in `docs/threat-tracker/`. It uses browser JavaScript and the Python standard library. No additional packages or service subscriptions are required.

Each brief records exploitation requirements, affected versions, mitigation coverage, investigation guidance and source-backed relationships. Automatic data is displayed separately from reviewed assessments. Public repository mentions and matching rule paths remain unreviewed leads.

Word exports are real `.docx` files created in the browser. PDF export opens a printable report and uses the browser's print-to-PDF facility. Reports include source links, evidence status, review dates and collection errors. An optional author name is used only in the downloaded report. Word-export history and watchlists stay in browser storage; clearing browser data removes them.

Update reports use the previous Word-export request as their baseline. A browser cannot confirm that the user saved the file. Printing does not move that baseline. Reviewed milestones are retained alongside the latest 100 automatic changes per brief.

## Run and check

```text
python scripts/collect-threats.py --offline
python -m http.server 8080 --directory docs
node --test tests/*.test.mjs
python -m unittest discover -s tests -p test_threat_collector.py
```

Open `http://localhost:8080/threat-tracker/` for local review. To collect current sources, run `python scripts/collect-threats.py`. A GitHub token is optional locally and must be supplied through the environment. The scheduled workflow uses the repository's read-only token.

## Publishing and scheduled collection

The workflow checks public sources every four hours and deploys the complete `docs/` site, preserving the tool directory. Enable GitHub Actions as the repository's Pages publishing source before merging. The first merged push starts collection and deployment. GitHub's schedule is best effort and can be delayed or disabled after inactivity. Source health and last-success timestamps identify stale evidence.

The previous deployed snapshot is retrieved before collection so that history survives between deployments. If it cannot be retrieved, the checked-in snapshot is used. Failed sources retain their earlier evidence and last-success timestamps. Neither a fetch nor a matching CVE identifier updates an analyst review date.

CVE records, CISA KEV, FIRST EPSS, GitHub repository searches and matching paths in the Nuclei and Sigma repositories provide collection inputs. Vendor pages supply candidate CVE references. Matching a rule by filename has limited coverage: rules without a CVE in their path are not discovered. No exploit code is downloaded or executed. No production controls are deployed.

Add tracked vulnerabilities by editing `public/threat-tracker/briefs.json`. Include public sources and precise evidence labels. Candidates from shared vendor pages need review before entering this file. Update annual vendor archive URLs when required. Reviewed briefs, detection effectiveness and exploit-chain relationships require human assessment.

## Cost and reuse

The design uses a public repository, standard GitHub-hosted runners and GitHub Pages within their free-service limits. No custom domain is required. Providers can change limits or terms. Upstream data, repositories and rule licences remain with their respective publishers. The tracker links to research and rules rather than republishing exploit code or vendor articles.

## Evidence review and timelines

Exploit assessments record the source's claimed environment, prerequisites, outcome and limits. Public code reviews link to a pinned revision. Documentation review never becomes an independent reproduction claim. Controls map to explicit attack paths, retain testing status and can include candidate queries or rule examples. The Brotli WAF example is in Count mode and covers incoming encoding headers only.

PoC-in-GitHub adds repository discovery beyond the bounded direct search. CIRCL adds targeted dated reports for each selected CVE. Its upstream dates and exploitation claims remain unreviewed. No social report changes the reviewed exploitation assessment. Collector requests use a contact User-Agent, response/time limits and Retry-After deferrals; no CVE-space enumeration is performed. Up to 250 active/historical leads and 500 upstream timeline events are retained per CVE, with the bounds displayed.

The Timeline tab filters reviewed events and upstream reports separately. First-seen dates are preserved independently from source dates. Reports include late discoveries according to first-seen date, and preserve the original event date and source. CSV exports the filtered timeline; JSON includes the full current evidence plus the selected event delta. These exports do not move the Word report baseline.

The [investigation standard](RESEARCH-STANDARD.md) records the comparison baseline and evidence requirements. No universal superiority claim is made without a comparative evaluation.
