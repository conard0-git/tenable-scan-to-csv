# Tenable SC Scan Download (reference)

Endpoints, list/download mechanics, and the dedup + prune logic that
turns a scan-name list into a monthly CSV rollup.

## Endpoints

Two Security Center endpoints, both used via the `pytenable`
`TenableSC` client:

- `scan_instances.list()` — returns a `{"usable": [...], "manageable":
  [...]}` structure. The relevant scan instances are on `usable`. Each
  entry carries `id`, `name`, `status`, and `finishTime` (unix epoch
  seconds).
- `POST /rest/scanResult/{id}/download` — issued via `sc._session.post`,
  returns the ZIP archive bytes for a specific scan-result instance.
  The ZIP contains one `.nessus` XML file (the finding data) plus
  optional attachments the workflow does not consume.

## Authentication

Standard Security Center API-key auth via `pytenable`:

```python
TenableSC(
    url=os.getenv("<PREFIX>_URL"),
    access_key=os.getenv("<PREFIX>_ACCESS_KEY"),
    secret_key=os.getenv("<PREFIX>_SECRET_KEY"),
    verify=False,  # see Known limitations for the TLS caveat
)
```

The `<PREFIX>` is caller-supplied so the workflow supports single- and
multi-console setups without hardcoding a specific prefix.

## Finding the latest completed instance for a scan name

Filter `scan_instances.list().get("usable", [])` by:

1. `status.lower() == "completed"` — in-progress, paused, and errored
   instances are dropped.
2. **Normalized name equality.** Normalize both the caller's requested
   name and each candidate's `name` by lowercasing, stripping, and
   collapsing whitespace runs. Optionally apply known-alias fixups
   (e.g. `"networking devices"` ↔ `"network devices"`) if your
   organization has minor naming drift. Do not attempt fuzzy or regex
   matching — silent mismatches are worse than an explicit "not found"
   line in the log.

From the surviving candidates, pick the one with the largest
`finishTime` — that is the latest completed instance for the name.

## Downloading the scan ZIP

```python
resp = sc._session.post(f"{sc._url}/rest/scanResult/{scan_result_id}/download")
resp.raise_for_status()
zip_bytes = resp.content
```

The response body is the ZIP archive; hold it in memory for extraction.
A very large scan (multi-GB ZIP) can stress a low-RAM host — this is a
known limitation surfaced in the README.

## Extracting the `.nessus` XML

```python
with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
    nessus_filename = next(
        (f for f in z.namelist() if f.endswith(".nessus")), None
    )
    if not nessus_filename:
        # The archive did not contain a .nessus payload; log and skip.
        return
    nessus_xml_bytes = z.read(nessus_filename)
```

The archive should contain exactly one `.nessus` file. If it does not,
log the scan name and continue — this failure is per-scan, not fatal to
the run.

## Filename shape

The output CSV is named
`{safe_scan_name}_{YYYY-MM-DD}.csv`, where:

- `safe_scan_name` = the original scan name with any character not
  matching `[\w_.() -]` replaced by `_`, then trimmed. Preserves
  readability while staying filesystem-safe on macOS, Linux, and
  Windows.
- `YYYY-MM-DD` = the local-time date derived from `finishTime` (unix
  epoch seconds).

## Idempotency (skip-if-exists)

Before downloading, compute the expected filename and check whether it
already exists in the output directory:

```python
output_filename = monthly_dir / f"{safe_scan_name}_{scan_date_str}.csv"
if output_filename.exists():
    log.info(f"Latest version for '{scan_name}' ({scan_date_str}) already exists. Skipping.")
    continue
```

This is filename-based — the presence of the file is sufficient to skip.
Force a re-download by deleting the file. Do not add content-based
staleness checks (hash comparison, etag) — the whole point of the
workflow is "if the date on the file matches the latest scan, we are
done."

## Prune-on-write

After a successful CSV write, remove any earlier-dated versions of the
same scan from the output directory:

```python
for old_file in monthly_dir.glob(f"{safe_scan_name}_*.csv"):
    if old_file.resolve() != output_filename.resolve():
        old_file.unlink()
```

The output directory becomes a "latest per scan" snapshot rather than a
growing generational history. Callers who want a longitudinal record
should copy the file elsewhere between runs, or write to a different
`YYYY-Month` directory each cycle.

## Fallback date derivation

If the API returns `finishTime == 0` (or omits it entirely), the
filename computation would produce a `1970-01-01` timestamp. Fall back
to reading `HOST_END` tags from the `.nessus` file inside the ZIP:

1. Extract the `.nessus` XML from the ZIP.
2. Stream-parse for `<tag name="HOST_END">Sat May 25 10:30:00 2024</tag>`
   elements (format is `%a %b %d %H:%M:%S %Y`).
3. Keep the max epoch as the derived `finishTime`.
4. Recompute the filename with the derived date and re-check the
   idempotency guard before proceeding.

If neither source produces a usable date, fall back to "now" — the run
should never produce a file whose date is nonsense.

## Configuration surface (example)

- Console credentials via env vars (`<PREFIX>_URL`, `<PREFIX>_ACCESS_KEY`,
  `<PREFIX>_SECRET_KEY`).
- Scan-name list via env var (comma-separated) or a text file path
  (one scan per line; `#` comments; blank lines allowed).
- Column mapping via env var (JSON) or a text file path
  (`csv_header,xml_field` pairs). Required; no baked-in column set.
- Output directory root; defaults to `Results/{YYYY-Month}/` for the
  monthly rhythm.
- (Optional) a switch for TLS-verify mode when your SC console has a
  trusted cert.

Keep every site-specific value in the environment; never bake console
URLs, scan names, column mappings, or output paths into the workflow.
