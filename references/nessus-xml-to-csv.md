# Nessus XML → CSV (reference)

The `.nessus` XML structure, the streaming `iterparse` pattern used to
handle very large scans in flat memory, and the column-mapping semantics
that turn per-finding XML into per-row CSV.

## `.nessus` XML structure

The `.nessus` file is a `NessusClientData_v2` document containing a
`Report` element with one `<ReportHost>` child per scanned host. Each
`ReportHost` carries:

- A `<HostProperties>` block containing `<tag name="…">value</tag>`
  entries — this is where host-level facts live
  (`host-ip`, `host-fqdn`, `netbios-name`, `HOST_START`, `HOST_END`,
  operating-system fingerprints, etc.).
- One `<ReportItem>` per finding on that host. Each `ReportItem` carries
  finding-level info as **XML attributes** (`pluginID`, `severity`,
  `port`, `pluginName`, `pluginFamily`, …) and as **child elements**
  (`description`, `solution`, `cve`, `cvss3_base_score`,
  `cvss3_temporal_score`, and many more).
- Optional namespace-qualified child elements — most notably the
  compliance-check namespace
  (`{http://www.nessus.org/cm}compliance-check-name`) used by compliance
  scans.

The workflow emits **one CSV row per `ReportItem`**, joined with the
enclosing `ReportHost`'s properties as needed.

## Streaming parse (`iterparse`)

Real `.nessus` files routinely exceed hundreds of megabytes; a
full-document parse (`ET.fromstring`) will OOM on a low-RAM host. The
workflow uses `xml.etree.ElementTree.iterparse` on `('end',)` events and
processes each `ReportHost` at its closing tag, clearing the element
after use:

```python
ET.register_namespace("cm", "http://www.nessus.org/cm")
context = ET.iterparse(io.BytesIO(nessus_xml_bytes), events=("end",))
for _, host_elem in context:
    if host_elem.tag != "ReportHost":
        continue

    host_properties = {
        tag.attrib["name"]: tag.text.strip()
        for tag in host_elem.findall(".//HostProperties/tag")
        if tag.attrib.get("name") and tag.text is not None
    }

    for item in host_elem.findall(".//ReportItem"):
        row = build_row(item, host_properties, column_mapping)
        rows.append(row)

    # Critical: drop this ReportHost from memory before moving on.
    host_elem.clear()
```

Registering the `cm` namespace is what lets the caller reference
compliance-check fields with the `{http://www.nessus.org/cm}tag` XPath
form in their column mapping.

## Column mapping semantics

A column mapping is a set of `(csv_header, xml_field)` pairs. For each
pair, the workflow tries four sources in order and takes the first
non-null value:

1. **`ReportItem` attributes** —
   `item.get(xml_field)`. Covers `pluginID`, `pluginName`, `severity`,
   `protocol`, `port`, `svc_name`, `pluginFamily`, `pluginType`, and
   similar finding-level facts.

2. **`ReportItem` child elements** —
   `item.find(xml_field)` then `item.findtext(xml_field)`. Covers
   `synopsis`, `description`, `solution`, `see_also`, `plugin_output`,
   `risk_factor`, `cve`, `bid`, `xref`, `cvss_base_score`,
   `cvss3_base_score`, `cvss3_vector`, `stig_severity`,
   `exploit_available`, publication dates, and other free-form or
   scored fields.

3. **Host-level properties** —
   `host_properties.get(xml_field)`. Covers `host-ip`, `host-fqdn`,
   `netbios-name`, `mac-address`, `operating-system`, `HOST_START`,
   `HOST_END`, `system-type`, and any other `<HostProperties>` tag.

4. **Namespace-qualified elements** —
   if `xml_field` starts with `{`, treat it as a namespace-qualified
   XPath and use `item.find(xml_field).text`. This is how compliance
   scans surface check metadata:

   ```python
   COLUMN_MAPPING = {
       "Compliance Check Name": "{http://www.nessus.org/cm}compliance-check-name",
       "Compliance Result": "{http://www.nessus.org/cm}compliance-result",
       "Compliance Actual Value": "{http://www.nessus.org/cm}compliance-actual-value",
       "Compliance Policy Value": "{http://www.nessus.org/cm}compliance-policy-value",
   }
   ```

If none of the four sources match, the cell is left empty in the CSV.
Whitespace is trimmed on the extracted value; multi-line text is kept as
a single cell (Nessus emits newlines inside description/solution text —
the CSV writer must therefore quote fields).

### Example mappings (non-exhaustive)

The mapping is entirely caller-supplied — there is no baked-in column
set, and the tables below are **not a required schema**. Callers pick
any subset, any CSV header names, and any order. Fields that exist on
the `ReportItem` or `HostProperties` but are not listed here are still
valid; unmapped fields are simply omitted from the CSV.

**Finding attributes**

| CSV column (example) | XML field              |
| -------------------- | ---------------------- |
| `Plugin`             | `pluginID`             |
| `Plugin Name`        | `pluginName`           |
| `Severity`           | `severity`             |
| `Protocol`           | `protocol`             |
| `Port`               | `port`                 |
| `Service`            | `svc_name`             |
| `Plugin Family`      | `pluginFamily`         |
| `Plugin Type`        | `pluginType`           |

**Finding child elements**

| CSV column (example)       | XML field                  |
| -------------------------- | -------------------------- |
| `Synopsis`                 | `synopsis`                 |
| `Description`              | `description`              |
| `Solution`                 | `solution`                 |
| `See Also`                 | `see_also`                 |
| `Plugin Output`            | `plugin_output`            |
| `Risk Factor`              | `risk_factor`              |
| `CVE`                      | `cve`                      |
| `BID`                      | `bid`                      |
| `Xref`                     | `xref`                     |
| `CVSS Base Score`          | `cvss_base_score`          |
| `CVSS Temporal Score`      | `cvss_temporal_score`      |
| `CVSS V3 Base Score`       | `cvss3_base_score`         |
| `CVSS V3 Temporal Score`   | `cvss3_temporal_score`     |
| `CVSS V3 Vector`           | `cvss3_vector`             |
| `STIG Severity`            | `stig_severity`            |
| `Exploit Available`        | `exploit_available`        |
| `Exploitability Ease`      | `exploitability_ease`      |
| `Patch Publication Date`   | `patch_publication_date`   |
| `Vuln Publication Date`    | `vuln_publication_date`    |
| `Plugin Publication Date`  | `plugin_publication_date`  |
| `Plugin Modification Date` | `plugin_modification_date` |

**Host properties**

| CSV column (example) | XML field           |
| -------------------- | ------------------- |
| `IP Address`         | `host-ip`           |
| `DNS Name`           | `host-fqdn`         |
| `NetBIOS Name`       | `netbios-name`      |
| `MAC Address`        | `mac-address`       |
| `Operating System`   | `operating-system`  |
| `Host Start`         | `HOST_START`        |
| `Host End`           | `HOST_END`          |
| `System Type`        | `system-type`       |

**Compliance-check namespace** (`{http://www.nessus.org/cm}`)

| CSV column (example)      | XML field                    |
| ------------------------- | ---------------------------- |
| `Compliance Check Name`   | `compliance-check-name`      |
| `Compliance Result`       | `compliance-result`          |
| `Compliance Actual Value` | `compliance-actual-value`    |
| `Compliance Policy Value` | `compliance-policy-value`    |
| `Compliance Info`         | `compliance-info`            |
| `Compliance Solution`     | `compliance-solution`        |
| `Compliance See Also`     | `compliance-see-also`        |
| `Compliance Reference`    | `compliance-reference`       |
| `Compliance Audit File`   | `compliance-audit-file`      |
| `Compliance Check ID`     | `compliance-check-id`        |

Map namespace fields in the `{http://www.nessus.org/cm}tag` XPath form,
for example `{http://www.nessus.org/cm}compliance-result`.

## CSV writer

Use `csv.DictWriter` with `extrasaction="ignore"` so extra keys in the
row dict (from a mid-run mapping change, or a stub column that was
optional) do not blow up the write:

```python
with open(filename, "w", newline="", encoding="utf-8") as csvfile:
    writer = csv.DictWriter(
        csvfile, fieldnames=column_names, extrasaction="ignore"
    )
    writer.writeheader()
    writer.writerows(rows)
```

The `column_names` order must be the caller's requested column order —
`DictWriter` will emit them in exactly that order in the header and
every row.

## Empty-result handling

If the parse produces zero rows (a scan with no findings, or a truly
empty `.nessus` file), skip the CSV write and log a warning naming the
scan. Do not emit a header-only CSV — a zero-row file looks like a
successful export to downstream consumers and hides the "no findings"
signal.
