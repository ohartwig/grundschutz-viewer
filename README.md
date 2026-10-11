# grundschutz-viewer

Browse the BSI's machine-readable **Grundschutz++** catalog together with what
your own OSCAL documents say about it: one HTML page, no server, readable
offline.

It reads the chain that
[grundschutz-worksheets](https://github.com/ohartwig/grundschutz-worksheets)
writes -- the profile, the security plan (SSP), the assessment plan, assessment
results and the POA&M -- and follows each import through its back-matter to the
profile and the catalog, checking the SHA-256 it names. Which catalog, which
commit of the BSI library and which parameter values apply comes from the
profile, not from the viewer.

## Usage

```bash
go install github.com/ohartwig/grundschutz-viewer/cmd/grundschutz-viewer@latest

# A folder: read with all its subfolders. One folder per run makes a history.
grundschutz-viewer -o grundschutz.html runs/

# Single files work too, mixed with folders
grundschutz-viewer -o grundschutz.html security-plan.json results-*.json profile.json

# The register layout instead of the explorer
grundschutz-viewer -view register -o register.html runs/
```

| Flag | |
|---|---|
| `-o <file>` | The page to write, `-` for stdout. Default `grundschutz.html`. |
| `-view explorer\|register` | The layout. Default `explorer`. |
| `-offline` | Never fetch; read fetched files from the cache only. Without it, an import that is a URL and not among the inputs (usually the BSI catalog) is fetched, checked against its SHA-256 if one is named, and cached. |

JSON files that are not OSCAL, such as a check's raw output, are skipped.

### Runs and history

A run is a security plan and the documents next to it. Results in a
subdirectory without a plan of its own -- trial checks, for example -- belong
to the run of the nearest directory above them that has one. Runs are ordered
by the end of their results.

The newest run is the state the page shows; every run adds a point to the
history: per requirement the plan's status and the measured state, and per run
what changed against the run before.

### Imports

Each import is looked up next to the importing file, then by its SHA-256
among all inputs, then by file name. The page lists every import with its
state: checked against the SHA-256, without one, taken as the only candidate
in the same run, a different SHA-256, or missing.

The ISO 27001 column comes from a mapping collection among the inputs, or
else from the BSI's mapping at the catalog's commit.

## Building

```bash
go test ./...
go build ./cmd/grundschutz-viewer
```

## License

MIT, see [LICENSE](LICENSE).
