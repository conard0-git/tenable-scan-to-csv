---
name: tenable-scan-to-csv
description: >-
  Download the latest completed instance of each caller-supplied Tenable
  Security Center scan, extract the `.nessus` XML from the archive, and
  emit filtered-column CSVs into a dated monthly output directory.
  Idempotent by design — skips scans whose latest-dated CSV already exists
  and prunes older versions of a scan on rewrite. Well-suited for
  recurring named-scan CSV rollups on a monthly cadence. Use when asked
  to "export Tenable scans to CSV," "pull the latest scan results as
  CSV," "build a monthly CSV export from Tenable," or "convert .nessus
  files from Security Center to CSV."
license: MIT
---

# Tenable Scan to CSV

Turn a **caller-supplied list of Tenable Security Center scan names** into
a set of monthly CSV reports — one CSV per scan, containing the latest
completed instance's findings, filtered to a caller-supplied column set.
The workflow is deliberately narrow: it downloads, extracts, converts, and
files — no analysis, no scoring, no downstream mutation.

This is **Security Center-specific**. Tenable Vulnerability Management
(Tenable.io / cloud) uses a different scan-download API and result format
that this workflow does not target.

See `references/tenable-sc-scan-download.md` for the SC endpoint mechanics
(list scans, download the ZIP, dedup + prune logic) and
`references/nessus-xml-to-csv.md` for the `.nessus` XML structure, the
streaming `iterparse` pattern used for very large scans, and the
column-mapping semantics (attribute → child element → host-property →
namespace-qualified for compliance checks).

## When to use this

- **Recurring named-scan CSV exports.** The same set of scans, exported
  the same way, on a schedule, into a specific column format.
- **Feeding a downstream tool that consumes CSV.** A SIEM enrichment
  pipeline, an internal ticketing/handoff spreadsheet, a data-warehouse
  loader.
- **Sharing sanitized findings with an application owner.** Give them the
  CSV columns they can act on without exposing full Nessus internals.

## How to invoke

Invoke from Claude Code by name. The bare invocation reads every input —
console credentials, scan list, column mapping, output directory — from
the environment and produces the monthly export.

Bare invocation:

```
/tenable-scan-to-csv
```

Use a specific scan-list file (one scan name per line, `#` comments
allowed) instead of the environment default:

```
/tenable-scan-to-csv using scan list from ~/scan-list.txt
```

Override the column mapping for this run. Columns are caller-chosen —
any Nessus field the lookup can resolve is valid. A few shapes:

```
/tenable-scan-to-csv with columns Plugin,Severity,IP Address,CVE
/tenable-scan-to-csv with columns DNS Name,IP Address,Plugin Name,Solution,See Also
/tenable-scan-to-csv with columns DNS Name,Compliance Check Name,Compliance Result,Compliance Actual Value
```

See `references/nessus-xml-to-csv.md` for a larger (still
non-exhaustive) catalog of mappable fields.

Override output directory and force re-download (bypass the "latest CSV
already exists" idempotency check):

```
/tenable-scan-to-csv write to ~/reports/2026-08 and force re-download
```

## Inputs and prerequisites

- **Tenable Security Center API access** — URL + access/secret keys for
  the console. The API key must be able to list scan instances and
  download scan results (`GET /rest/scanResult/{id}/download`).
- **A scan-name list** — either an env var (comma-separated) or a text
  file path. Scan names are matched with light normalization
  (case-insensitive, whitespace-collapsed) so minor formatting drift in
  the console UI does not break lookup. Exact-match after normalization
  is required; fuzzy/regex matching is not supported.
- **A column mapping** — a required caller-supplied set of
  `(csv_column_name, xml_field_name)` pairs, either as an env var or a
  file. Any Nessus field the lookup order can resolve is valid; there
  is no baked-in column set. See `references/nessus-xml-to-csv.md` for
  the attribute → child element → host-property → namespace-qualified
  lookup and a non-exhaustive catalog of example mappings.
- **An output directory** — defaults to `Results/{YYYY-Month}/` for the
  monthly rhythm, overridable per run.
- Python with `pytenable` (SC client), plus `xml.etree.ElementTree`,
  `zipfile`, and `csv` from the standard library.
- Configuration via environment variables — no config files, no
  hardcoded scan names, column mappings, or output paths.

## The workflow

1. **Connect to the Security Center console.** Read the console URL and
   API keys from the env-var prefix (`PREFIX_URL`, `PREFIX_ACCESS_KEY`,
   `PREFIX_SECRET_KEY`). Fail fast with a clear message if any of the
   three are unset.

2. **Load the caller-supplied scan-name list.** From an env var
   (comma-separated) or a text file path. Strip blank lines and `#`
   comments; preserve the caller's original ordering.

3. **Load the column mapping.** From an env var or a file. Fail fast if
   neither is set — columns are an input, not a default. Each mapping
   entry pairs a CSV column header with the source XML field name
   (attribute name, child element tag, or host-property tag).

4. **For each scan name**, in the order the caller supplied:

   a. **Find the latest *completed* instance.** Call
      `scan_instances.list()` and filter to `status == "completed"` with
      a normalized-name match against the caller's requested name.
      **In-progress, paused, and errored instances are ignored by
      design** — partial results are worse than none.

   b. **Compute the expected CSV filename** as
      `{safe_scan_name}_{YYYY-MM-DD}.csv`, where the date is derived
      from the scan's `finishTime` (unix epoch → local `YYYY-MM-DD`).
      Sanitize scan-name characters that are unsafe on any common
      filesystem.

   c. **Idempotency check** — if that exact filename already exists in
      the output directory, **skip this scan** with an informational
      log line. This is the primary "already done" signal; deleting the
      file forces a re-download.

   d. **Download the scan ZIP** via
      `POST /rest/scanResult/{id}/download`. The response is a byte
      stream; hold it in memory for extraction (see Known limitations
      for the large-scan caveat).

   e. **Fallback date derivation.** If the API's `finishTime` is 0 or
      absent, open the downloaded ZIP, locate the `.nessus` file inside,
      and parse `HOST_END` tags to derive a plausible scan-completion
      timestamp. Re-check the idempotency guard with the corrected
      filename before continuing.

   f. **Extract the `.nessus` XML from the ZIP** in memory (the ZIP
      contains exactly one `.nessus` file plus optional attachments).

   g. **Stream-parse the XML** with `xml.etree.ElementTree.iterparse`
      on `('end',)` events. For every `ReportHost` closing tag, capture
      the `HostProperties/tag` entries into a host-properties dict.
      For each `ReportItem` child, walk the caller's column mapping:

      1. Check `ReportItem` attributes first
         (e.g. `pluginID`, `severity`, `port`).
      2. Then `ReportItem` child elements
         (e.g. `description`, `solution`, `cve`).
      3. Then host-level properties captured above
         (e.g. `host-ip`, `host-fqdn`, `netbios-name`).
      4. Then namespace-qualified elements — the compliance-check
         namespace (`{http://www.nessus.org/cm}`) is the concrete case;
         the mapping supports the `{ns}tag` XPath form.

      Clear each `ReportHost` element after processing (
      `elem.clear()`) so memory stays flat for very large scans.

   h. **Write the CSV** with the caller's column order preserved as the
      header. Create parent directories as needed.

   i. **Prune older versions of this scan.** After a successful write,
      remove any file in the output directory matching
      `{safe_scan_name}_*.csv` other than the just-written filename.
      This keeps the output directory a "latest per scan" snapshot
      rather than accumulating monthly generations.

5. **Per-scan failures are non-fatal.** A single scan's download, parse,
   or write error logs and skips to the next scan. The run always tries
   to produce output for every scan that succeeds.

## Design rules

- **Read-only against Tenable** — the workflow only lists and downloads
  scan results; it never creates, launches, modifies, or deletes scans,
  scan policies, assets, or findings on the console.
- **Idempotent by filename.** The presence of the expected
  `{scan}_{YYYY-MM-DD}.csv` in the output directory is sufficient to
  skip that scan. Force a re-download by deleting the CSV; do not add
  content-based staleness checks.
- **Streaming XML.** Always use `iterparse` and `elem.clear()` — never
  `ET.fromstring` on the full `.nessus` XML. Real scans routinely exceed
  hundreds of megabytes; a full-parse implementation will OOM on a
  low-RAM host.
- **Caller-supplied lists.** Scan names, column mappings, and output
  paths are inputs — never bake site-specific values (scan names, org-
  internal column choices, network CIDRs) into the workflow.
- **Missing config is a fail-fast for the console and the column
  mapping, a warn-continue for the scan list.** Missing console vars or
  a missing column mapping stop the run with a clear error; a missing
  scan is logged with the scan name and skipped so the rest of the
  batch still produces output.

## Output

- One CSV per scan in the monthly output directory
  (`Results/{YYYY-Month}/{safe_scan_name}_{YYYY-MM-DD}.csv` by default).
- Console logs recording each scan's outcome (downloaded / skipped as
  already-latest / not-found / error), plus the parsed row count per CSV.
