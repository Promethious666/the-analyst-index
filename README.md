# The Analyst Index

The Analyst Index is a privacy-friendly directory for choosing open-source cybersecurity tools with operational context. It helps defenders search by task or evidence, compare practical trade-offs, and inspect limitations before opening an upstream repository.

## What it is

- A curated navigation aid, not an endorsement or security guarantee.
- A static website with local search, filtering, comparisons and a device-local watchlist.
- A catalogue that distinguishes reviewed entries from automatically discovered candidates.
- A zero-cost project with no accounts, telemetry, paid APIs, AI dependency or hosted database.

## Run locally

Install Node.js 22 or later, then run:

```text
npm ci
npm run dev
```

Open the local address printed by the development server. To validate a change, run `npm test`, `npm run lint` and `npm run build`.

## Catalogue policy

The visible catalogue is editorially curated. Automated discovery output is quarantined and cannot add, modify or endorse a visible entry. Always confirm upstream documentation and obtain appropriate authorisation before using active security tooling.

See [METHODOLOGY.md](METHODOLOGY.md) for evidence labels, inclusion rules and limitations. Security concerns should be reported according to [SECURITY.md](SECURITY.md).

## Licence

Site code and original catalogue text are provided under the MIT License. Upstream tools retain their own licences and are not redistributed by this project.
