# Henry — a DPRK threat intelligence corpus

Snapshot of 2026-09-17T04:17:09Z. Rebuilt daily.

Reports, indicators, incidents, the structured extraction behind each
report, and the full text of the documents themselves. Published for
anyone doing longitudinal or corpus-scale work on DPRK cyber activity,
which is hard to do from a feed.

## What is here

Everything is gzipped under `data/`. CSV where the shape is flat,
JSONL where it is not; the JSONL is authoritative, the CSV flattens
JSON array columns to space-separated strings.

| file | rows | size | what it is |
|---|---:|---:|---|
| `reports` | 17,851 | 10 MB | Threat reports: metadata, our summary, and the structured fields extracted from each. |
| `texts` | 14,533 | 167 MB | Full document text, one JSON object per line, sharded by year. `henry-texts-feed-references` is different in kind: pages fetched from indicator feed URLs, including CDN assets and parked domains. Keep them apart in any analysis. |
| `extractions` | 14,647 | 17 MB | The full structured extraction per report: victimology, MITRE techniques, malware, infrastructure, hunting guidance and the analytical reasoning behind them. |
| `indicators` | 168,018 | 23 MB | Network, file and on-chain indicators. `disposition` says what each one IS -- see below; do not build a blocklist without reading it. |
| `indicator_reports` | 68,914 | 10 MB | Which indicator appeared in which report, with the provenance tier of that link. |
| `incidents` | 1,754 | 2 MB | Curated incidents, deduplicated. Several reports of one event are merged; `merged_count` and `merged_from` say so. |
| `events` | 4,807 | 3 MB | The channel stream as filed, one row per report, undeduplicated. |
| `artefacts` | 72,627 | 10 MB | Hunting artefacts pulled from report prose: mutexes, paths, filenames, registry keys, yara/sigma terms. |
| `actors` | 10 | 0 MB | The actor taxonomy, with per-actor counts. |
| `research` | 5 | 0 MB | Precomputed corpus-level findings, each with the conditions under which it fails. |

```python
import gzip, json
with gzip.open('data/henry-reports.jsonl.gz', 'rt') as fh:
    reports = [json.loads(line) for line in fh]
```

## Things that will mislead you

**Most reports have no full text.** The corpus holds metadata and a
summary for all 17,851 reports, and
mirrored text for 14,533 documents.
Absence of text is not absence of a report.

**`disposition` on an indicator is not severity.** `malicious` is
attacker-controlled. `dual_use` is a legitimate service the actor used
-- GitHub, Google Drive, Telegram -- where the path is the finding and
the host must never be blocked. `reference` is where the reporting
lives. `noise` is not an indicator at all. `unknown` means no basis to
say, and is where a genuinely new C2 appears first.

**Loss figures are what a report stated**, never what was confirmed,
and reports of one event routinely disagree. Summing them across
incidents overstates badly: seizures and laundering volumes are not
thefts, and most incidents here carry no DPRK attribution at all.
Check `dprk_nexus` before treating a total as DPRK losses.

**Counts are what was reported, not what happened.** A year with more
reporting looks like a year with more activity.

**An actor assignment is this corpus's reading** of a report unless
the report names the actor itself. `publisher` is the reporting
source.

**A few documents are truncated.** Text is capped at 2 MB per
document; `truncated` and `text_length_original` mark the ones
affected. They are scrape failures, not long articles.

## Provenance

Indicators carry a provenance tier: `confirmed` where our extraction
and the publisher independently agree, `extracted` where only ours
did, `published` where only theirs did. For hunting you usually want
everything; for a published claim you want `confirmed`.

## Licence

The structured data, summaries and extractions are ours and are free
to use with attribution. The document text is the work of its
publishers, mirrored here for research; `source_url` is on every
record and rights remain theirs.
