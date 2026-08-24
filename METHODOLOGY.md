# Methodology

## Purpose

The Analyst Index helps an analyst find plausible tools and understand operational trade-offs. It does not certify a tool as secure, suitable, maintained or effective for a particular environment.

## Evidence model

Visible entries identify an upstream repository and record an editorial summary, typical interaction mode, data path, setup effort, delivery format, platforms, outputs and a material limitation. Repository existence is machine-checkable; summaries and classifications are editorial judgements and can become outdated.

Automated discovery uses an allowlist of established security collections. Discovery is not endorsement: it establishes only that a project was referenced by a source. Candidates remain quarantined until their purpose, provenance, licence, maintenance posture, operational behaviour and wording have been assessed.

## Inclusion criteria

A visible entry should:

1. Have a stable, attributable upstream project.
2. Provide a material defensive-security or authorised-assessment use case.
3. Be described without promotional or unverifiable claims.
4. State active interaction and external data transfer where applicable.
5. Include at least one meaningful limitation.

An entry may be removed or marked stale when its repository disappears, becomes archived, changes purpose, loses clear licensing or presents unresolved security concerns.

## Automation

The weekly health workflow validates the site, checks visible repositories, and produces quarantined discovery evidence. It has read-only repository permissions, pinned third-party actions, bounded runtime and no path that edits the trusted catalogue. A failed check preserves the last-known-good site.

GitHub can disable scheduled workflows after prolonged repository inactivity. The static site continues to work if that happens, but evidence freshness will stop advancing until automation is restored.

## Safety

Entries marked Active can contact, enumerate or change systems and may trigger monitoring. Users are responsible for permission, scope, rate limits, data protection, tool isolation and validation of results.
