# Security policy

Please report a vulnerability through GitHub's private vulnerability reporting feature when it is available for this repository. Do not include live credentials, personal data, malware samples or confidential client information in a public issue.

The project is a static directory and does not accept uploaded evidence or process investigation data. Reports concerning an indexed third-party tool should normally be sent to that tool's maintainers; this project can separately correct or remove its catalogue entry.

Only the latest version on the default branch is supported during private development.

## Dependency review — 3 October 2026

Patched dependencies and the lockfile are validated with catalogue tests, linting,
and a production build. The package manager is pinned for reproducible installs.
Development servers must stay local and must not be exposed to the internet.

One upstream issue remains open: [CVE-2026-93687 in braces](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm).
The maintainer has not published a patched release. It is a build-time dependency
used by glob tooling, not a service deployed by the static GitHub Pages website.
Only repository-controlled glob patterns are used; never pass remote catalogue
content or visitor input into build/lint glob patterns. Keep the alert open until
an upstream patch or a tested replacement is available. This restriction reduces
exposure but does not make the vulnerable package fixed.
