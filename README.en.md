# shirokuma-sast

[**日本語**](README.md) · **English**

**An interprocedural taint-analysis SAST engine for TypeScript / JavaScript.**

This is not a regex tool that greps for dangerous function names.
It parses real ASTs with the TypeScript compiler API, builds a dataflow graph, and
tracks **where untrusted input enters, how it propagates, and which dangerous
operation it reaches**.

```
$ shirokuma scan .

shirokuma-sast 0.1.0 — 3 findings (error 2 / warning 1 / note 0)

[error] sql-query  src/app.ts:8:3
  Untrusted input reaches `query()` (SQL injection)
  cwe: CWE-89
  advice: Use placeholders ($1 / ?) instead of building queries by concatenation.
  ├─ source    src/app.ts:6:15  req.query.id (Express: query string value)
  ├─ propagate src/app.ts:6:9   id
  ├─ propagate src/app.ts:7:34  'SELECT * FROM users WHERE id = ' + id
  ├─ propagate src/app.ts:7:9   sql
  └─ sink      src/app.ts:8:3   db.query
```

Every finding ships with the actual source→sink path. That path is the single most
time-consuming part of triaging SAST output — deciding whether a warning is
reachable — and this engine answers it in the finding itself.

[![CI](https://github.com/shiyuanyeming-hub/shirokuma-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/shiyuanyeming-hub/shirokuma-sast/actions/workflows/ci.yml)

---

## Why dataflow instead of AST pattern matching

Grepping for `req.query` and then looking for `db.query` in the same function takes
about 200 lines. It breaks on all three of these:

```ts
// 1. through a variable
const id = req.query.id;
const sql = 'SELECT * FROM users WHERE id = ' + id;
db.query(sql);

// 2. across a function boundary
function buildQuery(raw: string) { return 'SELECT * FROM orders WHERE c = "' + raw + '"'; }
db.query(buildQuery(req.query.customer));

// 3. through a sanitizer (i.e. safe)
const safe = escapeHtml(req.query.comment);
element.innerHTML = '<p>' + safe + '</p>';
```

This engine handles all three: it reports 1 and 2, and stays silent on 3.
Not reporting safe code matters as much as reporting unsafe code.

## What it does

| Capability | Detail |
| --- | --- |
| Interprocedural analysis | Follows taint across functions, methods and classes |
| 16 propagation forms | Assignments, concatenation, templates, destructuring, spread, returns, higher-order calls |
| Sanitizer semantics | `escapeHtml` clears only `html`; parameterised `db.query` clears only `sql` |
| Sanitizer usage validation | `db.query(sqlVar)` is judged **invalid** — the taint survives |
| Explainable findings | Every finding carries a source → propagate → sink proof |
| SARIF 2.1.0 output | GitHub Code Scanning renders the path natively |
| Externalised rules | Add sources/sanitizers/sinks in `.shirokuma.yml` |
| Deterministic output | Identical input yields byte-identical reports |
| Measured accuracy | Precision/recall measured against a labelled corpus |

## Detected vulnerability classes

`shirokuma rules` lists all 147 sinks.

| Class | Examples |
| --- | --- |
| CWE-89 SQL injection | `db.query`, `connection.query`, `sequelize.query`, `knex.raw`, Prisma `$queryRawUnsafe` |
| CWE-79 XSS | `innerHTML`, `outerHTML`, `document.write`, `res.send`, `dangerouslySetInnerHTML` |
| CWE-78 OS command injection | `child_process.exec`, `execSync`, `spawn`, `execFile` |
| CWE-22 path traversal | `fs.readFile`, `fs.writeFile`, `res.sendFile`, `res.download`, 40 fs APIs in total |
| CWE-94 code injection | `eval`, `new Function`, `vm.runInNewContext` |
| CWE-943 NoSQL injection | `find`, `findOne`, `updateOne`, `$where`, `aggregate` |
| CWE-601 open redirect | `res.redirect`, `location.assign` |
| CWE-918 SSRF | `fetch`, `axios.get`, `http.request` |

47 sources cover Express / Koa / Fastify / AWS Lambda, browser APIs
(`location`, `document.cookie`, `window.name`) and Node (`process.argv`, `process.env`).

## Quick start

Node.js 20.11 or newer.

```bash
git clone https://github.com/shiyuanyeming-hub/shirokuma-sast.git
cd shirokuma-sast
npm install
npm run build

node dist/cli/main.js scan /path/to/your/project
```

Or link it as a command:

```bash
npm link
shirokuma scan .
```

### Common usage

```bash
# Human-readable output (default)
shirokuma scan .

# CI: emit SARIF and fail on warnings or worse
shirokuma scan . --format sarif --output results.sarif --fail-on warning

# Narrow the scope and the tags
shirokuma scan src --include 'src/**/*.ts' --exclude 'src/generated' --max-call-depth 5

# List built-in rules
shirokuma rules --json

# Ask what a specific line is classified as (debugging aid)
shirokuma explain src/app.ts:42
```

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings, or none at/above `--fail-on` |
| `1` | Findings at/above `--fail-on` |
| `2` | Argument, configuration, or runtime error (e.g. target does not exist) |

`2` is kept separate from `1` so CI never confuses "found vulnerabilities" with
"the analysis itself failed".

## Library usage

```ts
import { scan, createReporter } from 'shirokuma-sast';

const result = await scan({ root: process.cwd() });

for (const finding of result.findings) {
  console.log(finding.ruleId, finding.relativePath, finding.range.start.line);
  for (const step of finding.proof) {
    console.log(' ', step.role, step.label, `${step.range.start.line}:${step.range.start.column}`);
  }
}

const sarif = createReporter('sarif').render(result);
```

## How it works

```text
TypeScript AST
      │
      ▼
  1. IR construction (src/ir/)      AST → dataflow graph. No rule knowledge.
      │
      ▼
  2. Rule annotation (src/rules/)   Which node is a source / sanitizer / sink.
      │
      ▼
  3. Taint propagation (src/analysis/)  Worklist to a fixpoint; tags cleared
      │                                 per sanitizer; proof path recorded.
      ▼
  4. Reporting (src/reporters/)     pretty / json / sarif / markdown
```

Design notes — including the bugs found while building it (parameter position
resolution, self-edges on dynamic keys, nested sink duplication) — are in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

<!-- BENCHMARK:START -->

| Metric | Value |
| --- | --- |
| Precision | **91.3%** |
| Recall | **100.0%** |
| F1 | **0.955** |
| True / false positives / false negatives | 21 / 2 / 0 |

Scope: 31 files / 45 functions / 45ms. Corpus: 21 vulnerable and 13 safe cases.

By vulnerability family:

| Family | Precision | Recall | TP/FP/FN |
| --- | --- | --- | --- |
| `code` | 100.0% | 100.0% | 2/0/0 |
| `command` | 100.0% | 100.0% | 3/0/0 |
| `html` | 83.3% | 100.0% | 5/1/0 |
| `nosql` | 100.0% | 100.0% | 2/0/0 |
| `path` | 100.0% | 100.0% | 2/0/0 |
| `sql` | 100.0% | 100.0% | 5/0/0 |
| `url` | 66.7% | 100.0% | 2/1/0 |

Remaining errors (stated plainly):

- **False positive**: `clean/path-basename.ts:10` (`xss-res-send`)
- **False positive**: `clean/redirect-whitelist.ts:10` (`redirect-res`)

Last updated: 2026-10-08 (reproducible via `npm run bench`)
<!-- BENCHMARK:END -->

Scoring definitions:

- **Precision** = TP / (TP + FP) — of what we reported, how much was real
- **Recall** = TP / (TP + FN) — of what was real, how much we reported
- Findings on cases labelled *safe* count as false positives, so the metric
  reflects whether sanitizers are actually understood

## Configuration

Drop `.shirokuma.yml` in your project root to **extend** the built-in rules
(it appends, it does not replace). Full syntax in
[docs/shirokuma.example.yml](docs/shirokuma.example.yml).

```yaml
rules:
  sources:
    - id: internal-ticket-header
      member: req.headers.x-internal-ticket
      kinds: [sql, html]

  sanitizers:
    # Only valid when argument 0 is a literal (i.e. placeholder usage)
    - id: internal-sql-builder
      member: db.sql
      kinds: [sql]
      validation: static-sql

  sinks:
    - id: custom-report-render
      member: report.render
      kinds: [html]
      severity: warning
      cwe: [CWE-79]
      message: Unvalidated HTML is rendered into a report
      taintedArgs: [1]   # only inspect the 2nd argument (0-based)

output:
  failOn: error
```

## GitHub Code Scanning

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  sast:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci && npm run build
      - run: node dist/cli/main.js scan . --format sarif --output results.sarif --fail-on none
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

`partialFingerprints` carries the stable finding ID, so a re-run reports the same
issue as "ongoing" rather than "new".

## Development

```bash
npm install
npm run build        # compile to dist/
npm run typecheck    # strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes
npm test             # 484 tests
npm run bench        # measure precision/recall, write reports/, update this README
npm run selfscan     # scan this repository with itself (dogfooding)
```

## Known limitations

Stated plainly — hiding these would mislead anyone who actually runs the tool.

- **No type information.** Only single-file ASTs are read. Propagation across npm
  packages is not followed; imported function bodies are out of scope.
- **Limited flow sensitivity.** Branch reachability and exceptions are not modelled.
  A `db.query(sql)` inside `if (isAdmin)` is reported even if it is unreachable in practice.
- **No guard recognition.** Allow-list checks such as
  `ALLOWED.has(target) ? target : '/home'` are not treated as sanitizers
  (this is one of the two remaining false positives in the benchmark).
- **String contents are not inspected.** `parseInt` is understood to produce a
  number, but "is this string safe SQL" is not decided.
- **`res.send` / `res.redirect` are warning-level.** They report any taint that
  reaches them, so responses never interpreted as HTML are also flagged.
- **Taint analysis is not sound.** Misses are inevitable. The precision/recall
  figures above are measured on the bundled corpus and are not a guarantee for
  every codebase.

## License

MIT — [LICENSE](LICENSE)
