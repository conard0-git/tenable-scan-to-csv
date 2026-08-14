# Tenable Scan to CSV

> Download the latest completed instance of each caller-supplied Tenable Security Center scan, extract the `.nessus` XML, and emit filtered-column CSVs to a dated monthly directory. Idempotent by design.

A Claude Code / Agent Skills skill that turns a caller-supplied list of
Tenable Security Center scan names into a set of monthly CSV reports —
one CSV per scan, containing the latest completed instance's findings,
filtered to a caller-supplied column set. Downloads only what is new,
prunes older versions of each scan on rewrite, and streams the underlying
`.nessus` XML so multi-hundred-megabyte scans process in flat memory.

## Why

Recurring named-scan CSV exports have a common shape: the
same set of scans, exported the same way, on the same cadence, into the
same columns, to be handed off to a downstream tool. Doing
this by hand from the Security Center UI is tedious and error-prone — a
scan gets missed, a column is off, last month's file gets overwritten
without a fresh timestamp. This skill mechanizes that pipeline while
staying deliberately narrow: it downloads, extracts, converts, and files.
No analysis, no scoring, no downstream mutation.

## What it does

1. Connects to a Tenable Security Center console using env-var-supplied
   API keys.
2. Reads a caller-supplied scan-name list (env var or file).
3. For each scan name, in the order supplied:
   - Finds the latest **completed** scan instance
     (`scan_instances.list()` filtered by status + normalized name).
   - Computes the expected CSV filename
     `{safe_scan_name}_{YYYY-MM-DD}.csv` from the scan's `finishTime`.
   - **Skips** the download entirely if that exact CSV already exists.
   - Otherwise downloads the ZIP, extracts the `.nessus` XML in memory,
     stream-parses it (`iterparse` on `end` events), and maps each
     `ReportItem` to the caller's column set.
   - Writes the CSV and prunes older versions of the same scan.
4. Falls back to parsing `HOST_END` tags from the `.nessus` file when the
   API's `finishTime` is missing or invalid, so output filenames always
   carry a real scan-completion date.

See `SKILL.md` for the full workflow,
`references/tenable-sc-scan-download.md` for the SC endpoint mechanics
and dedup / prune logic, and `references/nessus-xml-to-csv.md` for the
`.nessus` XML structure, streaming-parse pattern, and column-mapping
semantics.

## Read-only against Tenable

This skill only *reads* from Tenable Security Center — it lists scan
instances and downloads their results. It never creates, launches,
modifies, or deletes scans, scan policies, assets, or findings.

## Installation

```bash
# Global (available in all projects)
git clone https://github.com/conard0-git/tenable-scan-to-csv.git ~/.claude/skills/tenable-scan-to-csv

# Or per-project
git clone https://github.com/conard0-git/tenable-scan-to-csv.git .claude/skills/tenable-scan-to-csv
```

The folder must contain `SKILL.md` at its root.

## Prerequisites

- Tenable Security Center API access (URL + access/secret keys). The key
  must be able to list scan instances and call
  `POST /rest/scanResult/{id}/download`.
- Python with [`pytenable`](https://pytenable.readthedocs.io/) (for the
  SC client). `xml.etree.ElementTree`, `zipfile`, `csv`, and `pathlib`
  are standard library.
- A scan-name list (env var or text file). One scan name per line in
  file form; `#` comments and blank lines are allowed.
- A column mapping (env var or file) of `(csv_header, xml_field)` pairs.
  Required — there is no baked-in column set.

## Configuration

All configuration is environment-variable driven — no config files, no
hardcoded scan names, column mappings, or output paths.

Console credentials follow the same `(label, prefix)` convention used by
the other Tenable skills in this repository set:

- `<PREFIX>_URL` — Security Center base URL
  (e.g. `https://sc.example.com`).
- `<PREFIX>_ACCESS_KEY` — SC API access key.
- `<PREFIX>_SECRET_KEY` — SC API secret key.

Additional inputs (all optional; each has an env-var or file form):

- **Scan-name list** — comma-separated in an env var, or a text file
  path (`# ...` comments, one scan per line, order preserved).
- **Column mapping** — a required set of `(csv_header, xml_field)`
  pairs. Env-var form is a JSON blob; file form is one pair per line.
  Any Nessus field the lookup order can resolve is valid. See
  `references/nessus-xml-to-csv.md` for the lookup semantics and a
  non-exhaustive catalog of example mappings.
- **Output directory** — where CSVs are written; defaults to
  `Results/{YYYY-Month}/`.

## Example usage

Bare invocation — read every input from the environment and produce the
monthly export:

```
/tenable-scan-to-csv
```

Use a specific scan-list file for this run (bypasses the env default):

```
/tenable-scan-to-csv using scan list from ~/scan-list.txt
```

Override the column mapping for a one-off run. Columns are
caller-chosen — any Nessus field the lookup can resolve is valid:

```
/tenable-scan-to-csv with columns Plugin,Severity,IP Address,CVE
/tenable-scan-to-csv with columns DNS Name,IP Address,Plugin Name,Solution,See Also
/tenable-scan-to-csv with columns DNS Name,Compliance Check Name,Compliance Result,Compliance Actual Value
```

See `references/nessus-xml-to-csv.md` for a larger (still
non-exhaustive) catalog of mappable fields.

Override the output directory and force re-download (bypass the "latest
CSV already exists" idempotency guard):

```
/tenable-scan-to-csv write to ~/reports/2026-08 and force re-download
```

Each run prints a per-scan outcome line (downloaded / already-latest /
not-found / error) and the row count of every CSV written.

## Known limitations

Scope boundaries an operator should understand before relying on the
export:

- **Tenable Security Center only — not Tenable.io / Vulnerability
  Management.** The workflow uses `scan_instances.list()` and
  `POST /rest/scanResult/{id}/download`, which are Security Center
  endpoints. Tenable.io has a different scan-download API and result
  format that this workflow does not target.
- **Exact name matching (with light normalization) — a typo means the
  scan is silently skipped.** Scan names are matched case-insensitive
  and whitespace-collapsed. Fuzzy / regex matching is not supported;
  if a scan in your list does not match any completed instance
  exactly, the run logs "not found" and moves on. Double-check the
  spelling in your scan list if a scan mysteriously does not export.
- **Only *completed* scan instances are considered.** In-progress,
  paused, and errored instances are ignored by design — partial or
  errored results are worse than none. A scan
  that finished moments before the run may not appear if the console
  has not fully finalized its status yet.
- **Idempotency is filename-based, not content-based.** The presence of
  `{safe_scan_name}_{YYYY-MM-DD}.csv` in the output directory is
  sufficient to skip that scan. If the console re-issues a scan with
  the *same* `finishTime` but different content, the run will not
  detect it. Force a re-download by deleting the existing CSV.
- **TLS certificate verification is disabled by default.** The
  reference implementation calls the SC client with `verify=False`,
  which is common for on-prem SC consoles with self-signed certs. In
  environments with a properly-signed cert, enable verification — the
  workflow does not currently validate the console's TLS chain.
- **Scan ZIPs are downloaded in memory, not streamed to disk.** A very
  large scan (multi-gigabyte ZIP) may stress a low-RAM host. The XML
  parse itself is streaming — the memory ceiling is set by the ZIP,
  not the parse. If this becomes a real problem, extend the workflow
  to stream the download to a temp file.

## License

MIT — see `LICENSE`.
