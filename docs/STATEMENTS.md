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
output file is not overwritten unless `--force` is passed. Without `--force` the
completed temporary file is published with an atomic no-replace operation, so a
file created by another process is never silently destroyed. With `--force` the
destination is replaced atomically.

Text templates are read as UTF-8. Template files must be regular files and are
refused above 20 MiB. Rendered statements larger than 50 MiB are refused before
the output is written.

## Placeholders

Placeholders follow Python [`string.Template`](https://docs.python.org/3/library/string.html#template-strings)
syntax:

- `${field}` inserts the value of one field.
- `$$` inserts a literal dollar sign. A bare `$` that is not followed by a name,
  a braced name, or another `$` is an error, including in Word templates. Write
  `$$` for currency and other literal dollar signs.
- Every other name is rejected. The command exits with status `2` and lists
  every unknown placeholder.

Placeholders are replaced only in visible text (`w:t`) in the body, headers and
footers. Footnotes, endnotes, comments, field instructions (`w:instrText`) and
deleted text are copied unchanged; a placeholder in those locations is not a
substitution point.

Missing stored values render as `not available`. This text is also used when a
field does not apply to the CVE, for example `kev_due_date` when CISA KEV has no
entry. The reported-to-clients fields use the current stored mark from `watch report`.
After `watch unreport`, or without a mark, all three render `not reported`.

The default statement shows publication, first-seen and last-modified dates as
`YYYY-MM-DD` in UTC. Custom templates can use either the date-only fields or the
original full timestamps. Timestamps without a time-zone offset are treated as
UTC for the date-only fields; missing or invalid dates render `not available`.
Templates permit at most 100,000 placeholders or dollar escapes in total.
Unknown-name diagnostics list every unique unknown name up to 128 names and
16 KiB of identifier text; larger inputs stop with a resource-limit error.

## Fields

| Field | Meaning and example |
| --- | --- |
| `cve_id` | CVE identifier, for example `CVE-2026-1234`. |
| `title` | Record title. Current sources store no separate title, so this is always `not available`. |
| `description` | Description from the stored record, for example `Acme Widget before 4.2.1 allows unauthenticated remote code execution.` |
| `published` | NVD publication timestamp, for example `2026-10-28T10:00:00.000`. |
| `published_date` | Publication date in UTC, for example `2026-10-28`. |
| `first_seen` | When the CVE first entered this watch database, for example `2026-11-04T14:00:00+00:00`. |
| `first_seen_date` | First-seen date in UTC, for example `2026-11-04`. |
| `last_modified` | NVD last-modified timestamp, for example `2026-11-03T08:30:00.000`. |
| `last_modified_date` | Last-modified date in UTC, for example `2026-11-03`. |
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
| `kev` | `yes` when CISA KEV or EU KEV stores an entry with a date added, otherwise `no`. |
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
| `reported` | `yes` when currently marked as reported to clients, otherwise `not reported`. |
| `reported_by` | Who made the current report mark, for example `operator@example.invalid`; `not reported` without a mark. |
| `reported_at` | Full timestamp of the current report mark, for example `2026-11-04T14:00:00+00:00`; `not reported` without a mark. |

Values come from the same stored view used by alert messages and the current
local report mark. The command does not query NVD, EUVD, KEV, or EPSS.

## Word templates

A `.docx` template is an ordinary Word document with `${field}` placeholders in
its text. Placeholders work in:

- body paragraphs, including content controls, nested text boxes and table
  cells;
- headers and footers (`word/header*.xml` and `word/footer*.xml`);
- text that Word has split across several formatting runs, which is common when
  a placeholder was typed with different spell-check or formatting state. The
  rendered value keeps the formatting of the first run that held placeholder
  text; consumed runs are emptied.

Alternate namespace prefixes and a default WordprocessingML namespace work as
long as the element is bound to the standard WordprocessingML namespace. Text
inside a nested paragraph is treated as its own paragraph, so a placeholder
cannot span two paragraphs.

Multi-line values, such as `references` or `cvss_all`, become line breaks in the
same run. CRLF and CR are treated as line breaks. Values are XML-escaped.
Paragraphs without placeholders and every other package member are copied
byte-for-byte, and `[Content_Types].xml` stays first in the archive.

Limits and restrictions:

- the `.docx` file must be at most 20 MiB;
- packages may contain at most 10,000 members, including directory entries;
- one uncompressed member must be at most 50 MiB and the whole archive at most
  200 MiB; complete compressed streams are checked against the declared sizes
  and checksums, and inconsistent members are refused;
- rendered document, header and footer XML together must fit 50 MiB, including
  escaped text, repeated text attributes and line-break markup;
- XML must use UTF-8 or UTF-16; its original encoding is preserved;
- XML members are limited to 8 MiB each and 32 MiB together, with nesting at
  most 256 elements deep;
- elements and attributes (including namespace declarations) together are
  limited to 100,000 per XML member and 200,000 per package;
- attributes are limited to 8,192 and 256 KiB of source bytes per element,
  50,000 and 1 MiB per XML member, and 100,000 and 4 MiB per package; attribute
  byte limits conservatively include surrounding whitespace and a self-closing
  slash, but exclude the final `>`;
- namespace URI spellings are limited to 256 UTF-8 bytes. A conservative upper
  bound on expanded element/attribute names is checked before parsing: 16 MiB
  per XML member and 32 MiB per package, including both element callbacks. This
  charges every name against the longest namespace spelling in its member;
- duplicate package member names are refused;
- encrypted documents are refused;
- DTD and XML entity declarations are refused in every XML package member;
- only stored and DEFLATE ZIP members are supported; corrupt streams are refused;
- placeholders in footnotes, endnotes, comments and field instructions are not
  replaced.

An unknown name in a supported visible-text placeholder, a malformed `$`
sequence, or a component that cannot be parsed stops the command with status
`2`; the previous output file, if any, is left untouched.

Statements are not attached to watch notifications yet. Generate them on demand
and deliver the file through the channel you already use.
