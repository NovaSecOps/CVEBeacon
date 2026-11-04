# Statements

`cvebeacon watch statement` renders one CVE from the watch database into a
Markdown, plain-text, or Word document. A statement is generated on demand; it
never synchronises sources, evaluates rules, or delivers a notification.

```console
cvebeacon --config cvebeacon.toml watch statement CVE-2026-1234 --out statement.md
cvebeacon --config cvebeacon.toml watch statement CVE-2026-1234 \
  --template client-statement.docx --out CVE-2026-1234.docx
```

The CVE must already be stored. A missing CVE exits with status `2` and asks for
`watch sync`. Without `--template` the command uses the built-in Markdown
template shipped with the package.

## Templates

The template type follows the file extension:

| Template | Output | `--out` extension |
| --- | --- | --- |
| `.md`, `.txt` | text | `.md` or `.txt` |
| `.docx` | Word document | `.docx` |

Any other template or output extension is refused with status `2`. An existing
output file is not overwritten unless `--force` is passed. Output is written to
a temporary file in the destination directory and then replaced atomically, so
a failed render leaves the previous file untouched.

Text templates are read as UTF-8. Templates larger than 20 MiB are refused.

## Placeholders

Placeholders follow Python [`string.Template`](https://docs.python.org/3/library/string.html#template-strings)
syntax:

- `${field}` inserts the value of one field.
- `$$` inserts a literal dollar sign.
- Every other name is rejected. The command exits with status `2` and lists
  every unknown placeholder; it never leaves an unknown placeholder blank.

Missing stored values render as `not available`. This text is also used when a
field does not apply to the CVE, for example `kev_due_date` when CISA KEV has no
entry. The reported-to-clients fields render `not reported` because that mark is
not stored in the watch database yet.

## Fields

| Field | Meaning and example |
| --- | --- |
| `cve_id` | CVE identifier, for example `CVE-2026-1234`. |
| `title` | Record title. Current sources store no separate title, so this is normally `not available`. |
| `description` | Description from the stored record, for example `Acme Widget before 4.2.1 allows unauthenticated remote code execution.` |
| `published` | NVD publication timestamp, for example `2026-10-28T10:00:00.000`. |
| `first_seen` | When the CVE first entered this watch database, for example `2026-11-04T14:00:00+00:00`. |
| `last_modified` | NVD last-modified timestamp, for example `2026-11-03T08:30:00.000`. |
| `status` | `published` or `rejected`. |
| `cvss_max` | Highest stored CVSS base score across providers, for example `9.8`. |
| `cvss_max_provider` | Provider of the highest score: `NVD`, `CISA-ADP`, `EUVD`, `CNA: <source>`, or `Other`. |
| `cvss_max_version` | CVSS version of the highest score, for example `3.1`. |
| `cvss_max_vector` | CVSS vector of the highest score, for example `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. |
| `cvss_all` | One line per provider with a score, for example `9.8 v3.1 (NVD)`. |
| `severity` | Score band of `cvss_max`: `none` (rendered as `not available`), `low`, `medium`, `high`, or `critical`. |
| `epss` | EPSS probability with five decimals, for example `0.62214`. |
| `epss_percentile` | EPSS percentile with five decimals, for example `0.95421`. |
| `epss_date` | EPSS score date, for example `2026-11-03`. |
| `kev` | `yes` when CISA KEV or EU KEV lists the CVE, otherwise `no`. |
| `kev_date_added` | CISA KEV date added, or the EU KEV date added when only EU lists it, for example `2026-11-01`. |
| `kev_due_date` | CISA KEV remediation due date, for example `2026-11-20`. |
| `kev_required_action` | CISA KEV required action, for example `Apply the vendor update.` |
| `eu_kev` | `yes` when the EU KEV catalog lists the CVE, otherwise `no`. |
| `ssvc_exploitation` | Stored CISA-ADP SSVC exploitation value: `none`, `poc`, or `active`. |
| `cwes` | Comma-separated CWE identifiers, for example `CWE-79, CWE-89`. |
| `affected_products` | One line per product. When the stored view has exactly one vendor, each line is prefixed with that vendor, for example `acme widget`. With several vendors only product names are listed; with no products the vendor names are listed. |
| `references` | Reference URLs, one per line, for example `https://example.invalid/advisory`. |
| `nvd_url` | `https://nvd.nist.gov/vuln/detail/<cve_id>`. |
| `cve_org_url` | `https://www.cve.org/CVERecord?id=<cve_id>`. |
| `euvd_id` | EUVD identifier when the CVE has an EUVD item, for example `EUVD-2026-0001`. |
| `euvd_url` | `https://euvd.enisa.europa.eu/vulnerability/<euvd_id>` when available. |
| `generated_at` | Generation time in UTC, for example `2026-11-04T14:00:00+00:00`. |
| `reported` | Whether the CVE was reported to clients. Currently always `not reported`. |
| `reported_by` | Who reported the CVE to clients. Currently always `not reported`. |
| `reported_at` | When the CVE was reported to clients. Currently always `not reported`. |

Values come from the same stored view used by alert messages. The command does
not query NVD, EUVD, KEV, or EPSS.

## Word templates

A `.docx` template is an ordinary Word document with `${field}` placeholders in
its text. Placeholders work in:

- body paragraphs, including content controls and table cells;
- headers and footers (`word/header*.xml` and `word/footer*.xml`);
- text that Word has split across several formatting runs, which is common when
  a placeholder was typed with different spell-check or formatting state. The
  rendered value keeps the formatting of the first run that held placeholder
  text; consumed runs are emptied.

Multi-line values, such as `references` or `cvss_all`, become line breaks in the
same run. Values are XML-escaped. Paragraphs without placeholders and every
other package member are copied byte-for-byte, and `[Content_Types].xml` stays
first in the archive.

Limits and restrictions:

- the `.docx` file must be at most 20 MiB;
- one uncompressed member must be at most 50 MiB and the whole archive at most
  200 MiB;
- encrypted documents are refused;
- the standard `w:` namespace prefix is expected, as Word writes it.

An empty or missing placeholder is never silently ignored: unknown names and
malformed `$` sequences stop the command with status `2`.

Statements are not attached to watch notifications yet. Generate them on demand
and deliver the file through the channel you already use.
