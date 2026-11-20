# Investigation standard

The dashboard is assessed against the investigation it needs to support: identify an exploit, explain its requirements, review indicators, connect related issues, establish control coverage and export the findings. A claim of being better than every alternative requires evidence; it is not a product label.

## Baseline checked on 26 October 2026

| Project | Capabilities already documented | Required response |
| --- | --- | --- |
| [OpenCVE](https://docs.opencve.io/) | Product subscriptions, CVE history, alerts, KEV/EPSS, handling status and reports | Search, change tracking and exports are baseline features. |
| [Vulnerability-Lookup 6.3.0](https://www.vulnerability-lookup.org/2026/10/14/vulnerability-lookup-6-3-0/) | Related advisories, sightings, timelines, JSON export and a detection rules viewer | A timeline or a collection of rule links does not establish an advantage. |
| [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) | Broad automatic discovery of repositories mentioning CVEs | Reuse it as an additional discovery source; independently assess each claim. |

## Acceptance criteria

| Area | Required evidence |
| --- | --- |
| Exploit assessment | Source, reviewed revision for code, reported environment, requirements, outcome and limitations. Separate denial of service from code execution, and documentation review from reproduction. |
| Indicators | Value, type, source, context and evidence status. A stated review scope when no confirmed indicators were found. Never manufacture an indicator to fill an empty panel. |
| Controls | Map the attack path to the control. Record prerequisites, gaps, provenance and validation. A candidate query or provider claim must retain its status in every export. |
| Relationships | Explain whether issues share a release, component or mitigation. Do not infer an exploit chain from a shared CVE mention. |
| Timeline | Preserve event date, first-seen date, source and review status. Upstream dates stay unreviewed until checked. A report labelled exploited by an upstream source must not overwrite the assessment. |
| Research queue | Show unresolved questions and links awaiting review. Avoid invented completeness scores. |
| Export | Full and change Word/PDF reports, structured JSON and filtered timeline CSV. Include sources, revisions, limits and collection failures. Late discovery of an older event must appear in the next change report. |
| Collection | Retain evidence on failure, deduplicate sources, honour rate-limit deferrals and show bounded coverage. Collect only selected CVEs. |

The present implementation records source reviews and candidate controls. It does not provide independent exploit reproduction or live WAF/tenant validation. Those stages require recorded tests in an appropriate environment. Their absence remains visible, rather than being replaced by an optimistic status.

## Running cost

The application adds no paid service, account requirement or commercial API dependency. It uses the existing public repository, static Pages hosting and small scheduled jobs on standard runners. Provider terms and quotas can change. See [Actions billing](https://docs.github.com/billing/managing-billing-for-github-actions/about-billing-for-github-actions) and [Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits).
