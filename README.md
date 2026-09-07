# mcp-androzoo

An MCP server and a bulk downloader for [AndroZoo](https://androzoo.uni.lu/).

AndroZoo exposes two things over HTTP: an APK by SHA-256, and Google Play
metadata by package name. There is no search endpoint. Everything else —
selecting on package name, date, size, VirusTotal detection count or market —
happens against `latest.csv`, the catalogue you download once from
<https://androzoo.uni.lu/lists>. That file is scanned linearly on every query;
no database is built, so an answer always reflects the catalogue as it is on
disk, and its date bounds what you can find.

Requires an API key, issued to academic users at
<https://androzoo.uni.lu/access>.

## Tools

| Tool | Source | What it answers |
|---|---|---|
| `az_lookup` | catalogue | what AndroZoo records about these hashes (MD5, SHA-1 or SHA-256) |
| `az_search` | catalogue | which samples match a package fragment, a date range, a size range, a VT count, a market |
| `az_versions` | catalogue | every build of one package, oldest version code first |
| `az_gp_metadata` | live API | the Google Play records AndroZoo harvested for a package |
| `az_fetch_index` | live | download the catalogue itself, the prerequisite for the three above |
| `az_download` | live API | fetch APKs by SHA-256 into a directory |

Catalogue answers carry the file they came from and the scan statistics, so a
truncated result is never mistaken for an exhaustive one.

## Configuration

| Variable | Meaning |
|---|---|
| `ANDROZOO_API_KEY` | the API key; on macOS it can live in the keychain under the service name `androzoo.uni.lu` instead |
| `ANDROZOO_INDEX` | path to `latest.csv` or `latest.csv.gz` |
| `ANDROZOO_OUT` | default destination directory for downloads |

```json
{
  "mcpServers": {
    "androzoo": {
      "command": "/path/to/mcp-androzoo",
      "args": ["-index", "/data/androzoo/latest.csv.gz", "-out", "/data/apks"],
      "env": { "ANDROZOO_API_KEY": "..." }
    }
  }
}
```

The server starts without a catalogue; the three catalogue tools then refuse
rather than answer from nothing.

## Getting the catalogue

Nothing works without it, so both the CLI and the server can fetch it:

```sh
azdl -fetch-index ~/androzoo/latest.csv.gz
```

It is over 2.7 GB compressed, rebuilt nightly before 6am Luxembourg time, and
served as a public static file — no key needed for this one. The transfer lands
in a `.part` file and is renamed only once complete, so a run interrupted at
2 GB resumes where it stopped rather than starting over, and a half-written
file never gets mistaken for a catalogue. If the server will not resume — its
nightly rebuild landed in between — the download restarts and says so.

## azdl

Bulk downloads, from a file of hashes or straight from a catalogue query.

```sh
azdl -i hashes.txt -o ./apks -w 8
azdl -index latest.csv.gz -pkg-exact com.duiyun.cocospy -o ./apks
azdl -index latest.csv.gz -pkg-match cocospy -o ./apks -manifest selection.csv
azdl -index latest.csv.gz -vt-max 0 -market play.google.com -n 500 -random -seed 42 -dry-run
```

Each APK lands in a temporary file, is verified against its SHA-256 and only
then takes its final name, so an interrupted run leaves no truncated APK under
a valid name. Hashes already on disk are skipped, which makes a re-run a
resume. Concurrency is capped at 20, the ceiling AndroZoo asks for.

`-manifest` writes the selected catalogue rows next to the APKs — the record of
what a dataset was drawn from, which `-seed` makes reproducible.

## Caveats

- **`vt_detection` is a snapshot**, taken when AndroZoo scanned the sample, not
  a current verdict. A 0 means clean on that day.
- **Absence from the catalogue is not absence from AndroZoo**: your file may be
  older than the sample.
- **`markets` is provenance, not endorsement.** `play.google.com` means the APK
  was collected there at some point, not that it is there now.
- Downloaded APKs are live malware as often as not. They land on disk. Nothing
  here opens them.
