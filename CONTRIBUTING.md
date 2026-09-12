# Contributing

Thanks for helping maintain the LG TV blocklist. Two ground rules:

## 1. Evidence over guesses

This list is built from empirical observation, not speculation. Before adding
a domain, collect evidence:

- **Querylog**: AdGuard/Pi-hole log line showing the domain, who queried it,
  and when (a single random hit is not enough; boot-burst or heartbeat
  patterns are ideal).
- **Capture**: `dns.qry.name` or TLS SNI from a packet capture.
- **Repro**: what you did to trigger it (power-on, standby, app launch).

If you only have a hunch, open an issue with the `new-domain` template
instead of a PR — maintainers can verify from their own probes.

**Regional query logs are the most valuable evidence we can get.** Include
the region, timestamp, and client (TV model/name). The lists cover 49 country
codes, but only the German entries are traffic-observed — every other region
is a DNS-verified cross-product (see [Region coverage](#region-coverage)), so
a query log proving which hosts your TV actually contacts upgrades inference
to evidence.

To add a country code, verify it resolves first — `python scripts/verify.py`
checks every shipped entry over DNS-over-HTTPS, which matters because your own
Pi-hole/AdGuard would otherwise sinkhole these names and report them all dead.
Then add one line to `src/regions.txt`. Nothing else needs touching:
`scripts/build.py` cross-products it, and `scripts/localize.py` reads the same
file for its source labels.

## 2. Edit src/, never lists/

- `src/safe.txt` — telemetry/ad hostnames that are safe for stock TVs.
- `src/strict.txt` — the DELTA over safe (updates, ThinQ, LG Channels,
  weak-evidence entries). Do not repeat safe entries here.
- `src/zones.txt` — strict-only family apexes for whole-zone blocking in the
  adblock format.
- `src/regions.txt` — country codes with confirmed LG regional endpoints, one
  per line with the country name as its comment. Consumed by both scripts.

## Region coverage

LG runs a per-country endpoint matrix: `de.lgeapi.com`, `br.lgeapi.com`,
`jp.lgeapi.com` all exist. Rather than hand-write ~50 lines per family, tag
**one** audited entry with `[REGION-SCOPED]` in its annotation and
`scripts/build.py` expands it across every code in `src/regions.txt`:

```
de.nextlgsdp.com # SAFE: SDP region endpoint, telemetry [REGION-SCOPED]
```

That one line becomes 49 entries at build time. Rules:

- **The tag is explicit and never inferred from the hostname.** A two-letter
  first label does not mean "country": `ad.lgappstv.com` is an ad host on the
  store CDN, `am.`/`ig..lge.com` are unknown services, `su.lge.com` is the OTA
  server. Tagging one of those would emit ~50 bogus store-CDN entries and
  could break the Content Store for every user. CI has a test for this.
- **Audited entries win.** A hand-written entry is never replaced by its
  generated twin, so annotations and evidence survive.
- **Generated entries are DNS-verified, not observed.** Each built list's
  header states how many of its entries are generated. Do not describe them as
  observed anywhere.
- The tier follows the file: tag in `safe.txt` expands into SAFE, in
  `strict.txt` into the STRICT delta.

Every line needs an inline annotation — format, tags, and examples in
[Annotated domains](#annotated-domains) below.

CI validates every PR that touches `src/` or `scripts/` — structural
violations (malformed, duplicate, or non-LG hostnames) fail the build;
semantic tier placement is reviewed by maintainers. The generated `lists/`
directory is off-limits to PRs (CI rejects changes to it) — edit `src/`
instead.

## Format semantics

Matching differs per generated format:

- `-domains.txt` / `-hosts.txt`: **exact-name** — `snu.lge.com` blocks that
  host only, not the whole zone.
- `-adblock.txt`: `||snu.lge.com^` also matches subdomains of that name.
- Generated `-adblock.txt` files start with `#` metadata headers (title,
  date, entry count, license). AdGuard Home and uBlock Origin both treat
  those lines as comments; `!` is the canonical adblock comment prefix, so
  use `!` for comments when you extend a list in a custom filter.
- STRICT zone anchors (see `src/zones.txt`) only achieve whole-zone blocking
  in the adblock format; in domains/hosts they block the apex domain.

All three source files use exact-name, lowercase, wildcard-free entries
(see [section 2](#2-edit-src-never-lists)): `src/safe.txt` (SAFE),
`src/strict.txt` (STRICT delta), `src/zones.txt` (STRICT-only zone
anchors). So `-domains.txt` / `-hosts.txt` subdomain coverage depends on
enumeration. In the adblock format, zone anchors match region-prefixed
subdomains (`de.`, `us.`, …) — that is why STRICT is region-complete
there, while the exact-name formats cover only the region prefixes
present. Extending regional coverage is covered in [section
1](#1-evidence-over-guesses).

## Annotated domains

The source of truth is annotated: `src/safe.txt`, `src/strict.txt`,
`src/zones.txt`. Reading the comments there tells you what every entry does
and the evidence behind it; the [tier
table](README.md#which-list-should-i-use) in the README summarizes the
trade-offs.

Every line needs an inline annotation:

    snu.lge.com # STRICT: firmware OTA check server

Line format: hostname, space, `#`, space, `TAG: short description`. The
description names the function; entries with hard evidence add it after an
em-dash (`cdpbeacon.lgtvcommon.com # SAFE: ... (6-min heartbeat pattern
observed)`). Tags: `SAFE`, `STRICT`, `ZONE` (e.g. `lge.com # ZONE: umbrella
zone — kills all lge.com subdomains in adblock format`). Lowercase only, no
trailing dot, no wildcards — this list is exact-name (see [Format
semantics](#format-semantics)). Weak-evidence entries are tagged `weak` and
belong in strict.txt by policy.

## Workflow

1. Fork, branch off `main`.
2. Edit one or more files under `src/`.
3. Run `python3 scripts/build.py check && python3 scripts/test_build.py` locally
   (requires Python 3.10+ — the scripts use modern union type syntax).
4. Open the PR. The merge job regenerates `lists/` automatically — never
   commit generated files yourself.

## License

Content is CC BY 4.0, scripts MIT — see LICENSE and LICENSE-MIT.
