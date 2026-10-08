# shirokuma-sast

[**日本語**](README.md) · [English](README.en.md)

**TypeScript / JavaScript 向けの、クロスファンクション汚染解析（テイント解析）エンジン。**

正規表現で「危ない関数名」を探すツールではありません。
TypeScript のコンパイラ API で AST を読み、データフローグラフを組み、
**外部入力がどこから入って、どう流れて、どの危険な操作に到達したか** を追跡します。

```
$ shirokuma scan .

shirokuma-sast 0.1.0 — 検出 3 件（error 2 / warning 1 / note 0）

[error] sql-query  src/app.ts:8:3
  `query()` へ未エスケープの外部入力が到達しています（SQL インジェクション）
  cwe: CWE-89
  advice: プレースホルダ（$1 / ?）を使い、文字列連結でクエリを組み立てないでください。
  ├─ source    src/app.ts:6:15  req.query.id (Express: クエリ文字列（`?a=b`）由来の値。)
  ├─ propagate src/app.ts:6:9   id
  ├─ propagate src/app.ts:7:34  'SELECT * FROM users WHERE id = ' + id
  ├─ propagate src/app.ts:7:9   sql
  └─ sink      src/app.ts:8:3   db.query
```

**「なぜ危険と判定したか」が常に出力される** のが最大の違いです。
上の `├─` の並びがソースからシンクまでの実際の経路で、
SAST で最も時間を食う「本当に到達しうるのか」の確認作業を省きます。

[![CI](https://github.com/shiyuanyeming-hub/shirokuma-sast/actions/workflows/ci.yml/badge.svg)](https://github.com/shiyuanyeming-hub/shirokuma-sast/actions/workflows/ci.yml)

---

## なぜ AST ではなくデータフローなのか

「`req.query` を探して、同じ関数内に `db.query` があれば報告する」実装は 200 行で書けます。
しかし次の 3 つで必ず破綻します。

```ts
// 1. 変数を経由する
const id = req.query.id;
const sql = 'SELECT * FROM users WHERE id = ' + id;
db.query(sql);

// 2. 関数をまたぐ
function buildQuery(raw: string) { return 'SELECT * FROM orders WHERE c = "' + raw + '"'; }
db.query(buildQuery(req.query.customer));

// 3. サニタイザを通っている（＝安全）
const safe = escapeHtml(req.query.comment);
element.innerHTML = '<p>' + safe + '</p>';
```

本エンジンは 3 つとも正しく扱います。1 と 2 は検出し、3 は **検出しません**。
安全なコードを報告しないことは、危険なコードを見逃さないことと同じくらい重要です。

## できること

| 機能 | 内容 |
| --- | --- |
| クロスファンクション解析 | 関数・メソッド・クラスをまたいで汚染を追跡する |
| 16 種類の伝播 | 代入・連結・テンプレート・分割代入・スプレッド・戻り値・高階関数などを網羅 |
| サニタイザの意味論 | `escapeHtml` は `html` だけを、プレースホルダ付き `db.query` は `sql` だけを無害化する |
| サニタイザの用法検証 | `db.query(sqlVar)` は「プレースホルダのつもりで無効」と判定し、汚染を残す |
| 根拠の提示 | すべての検出がソース → 伝播 → シンクの経路を持つ |
| SARIF 2.1.0 出力 | GitHub Code Scanning が経路をそのまま表示できる |
| ルールの外部化 | `.shirokuma.yml` でソース／サニタイザ／シンクを追記できる |
| 決定的な出力 | 同一入力から常に同一のレポート（差分レビューと CI に向く） |
| 精度の実測 | 教師データ付きベンチマークで適合率・再現率を測る |

## 検出できる脆弱性

`shirokuma rules` で全 147 シンクを確認できます。

| 分類 | 例 |
| --- | --- |
| CWE-89 SQL インジェクション | `db.query` / `connection.query` / `sequelize.query` / `knex.raw` / Prisma `$queryRawUnsafe` |
| CWE-79 クロスサイトスクリプティング | `innerHTML` / `outerHTML` / `document.write` / `res.send` / `dangerouslySetInnerHTML` |
| CWE-78 OS コマンドインジェクション | `child_process.exec` / `execSync` / `spawn` / `execFile` |
| CWE-22 パストラバーサル | `fs.readFile` / `fs.writeFile` / `res.sendFile` / `res.download` ほか fs 系 40 種 |
| CWE-94 コードインジェクション | `eval` / `new Function` / `vm.runInNewContext` |
| CWE-943 NoSQL インジェクション | `find` / `findOne` / `updateOne` / `$where` / `aggregate` |
| CWE-601 オープンリダイレクト | `res.redirect` / `location.assign` |
| CWE-918 SSRF | `fetch` / `axios.get` / `http.request` |

汚染源（47 種）は Express / Koa / Fastify / AWS Lambda、ブラウザ API
（`location`・`document.cookie`・`window.name`）、Node（`process.argv`・`process.env`）を網羅します。

## クイックスタート

Node.js 20.11 以上が必要です。

```bash
git clone https://github.com/shiyuanyeming-hub/shirokuma-sast.git
cd shirokuma-sast
npm install
npm run build

# 自分のプロジェクトを解析する
node dist/cli/main.js scan /path/to/your/project
```

`npm link` すれば `shirokuma` コマンドとして使えます。

```bash
npm link
shirokuma scan .
```

### よく使う使い方

```bash
# 終端で読む（既定）
shirokuma scan .

# CI 用に SARIF を書き出し、warning 以上で失敗させる
shirokuma scan . --format sarif --output results.sarif --fail-on warning

# 特定ディレクトリだけ、タグを絞って
shirokuma scan src --include 'src/**/*.ts' --exclude 'src/generated' --max-call-depth 5

# 組み込みルールの一覧
shirokuma rules
shirokuma rules --json

# 「この行は何と判定されるか」を確認する（デバッグ用）
shirokuma explain src/app.ts:42
```

### 終了コード

| コード | 意味 |
| --- | --- |
| `0` | 検出なし、または `--fail-on` 未満 |
| `1` | `--fail-on` 以上の検出あり |
| `2` | 引数・設定・実行時のエラー（解析対象が存在しない等） |

`2` を `1` と分けているのは、CI が「脆弱性が見つかった」と
「解析に失敗した」を取り違えないようにするためです。

## ライブラリとして使う

```ts
import { scan, createReporter } from 'shirokuma-sast';

const result = await scan({ root: process.cwd() });

for (const finding of result.findings) {
  console.log(finding.ruleId, finding.relativePath, finding.range.start.line);
  for (const step of finding.proof) {
    console.log(' ', step.role, step.label, `${step.range.start.line}:${step.range.start.column}`);
  }
}

// SARIF を書き出す
const sarif = createReporter('sarif').render(result);
```

## 仕組み

```text
TypeScript AST
      │
      ▼
┌─────────────────────────────────────────────────────────┐
│ 1. IR 構築（src/ir/）                                    │
│    AST をデータフローグラフへ変換する。                      │
│    ノード = 値の発生点、辺 = 値の移動。                      │
│    ルールを一切参照しない。                                 │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│ 2. ルール適用（src/rules/）                               │
│    「どのノードがソース／サニタイザ／シンクか」を確定する。      │
│    構文木を走査しない。                                    │
└────────────────────┬────────────────────────────────────┘
                     ▼
┌─────────────────────────────────────────────────────────┐
│ 3. 汚染伝播（src/analysis/）                              │
│    ワークリスト法で不動点まで解く。                          │
│    サニタイザで該当タグだけを落とす。経路を記録する。           │
└────────────────────┬────────────────────────────────────┘
                     ▼
              Finding[]（根拠付き）
                     ▼
┌─────────────────────────────────────────────────────────┐
│ 4. レポート（src/reporters/）                             │
│    pretty / json / sarif / markdown                     │
└─────────────────────────────────────────────────────────┘
```

設計の詳細と、実装中に踏んだ不具合（仮引数の位置解決、動的キーの自己辺など）は
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) に書いています。

## 検出精度の実測

主張ではなく、実行して測った数値を載せています。
`benchmarks/` に教師データ（脆弱 21 箇所＋安全 13 箇所）があり、
`npm run bench` で再現できます。

<!-- BENCHMARK:START -->

| 指標 | 値 |
| --- | --- |
| 適合率 (precision) | **91.3%** |
| 再現率 (recall) | **100.0%** |
| F1 | **0.955** |
| 真陽性 / 偽陽性 / 偽陰性 | 21 / 2 / 0 |

対象: 31 ファイル / 45 関数 / 45ms。教師データは脆弱 21 箇所＋安全 13 箇所。

系統別:

| 系統 | 適合率 (precision) | 再現率 (recall) | TP/FP/FN |
| --- | --- | --- | --- |
| `code` | 100.0% | 100.0% | 2/0/0 |
| `command` | 100.0% | 100.0% | 3/0/0 |
| `html` | 83.3% | 100.0% | 5/1/0 |
| `nosql` | 100.0% | 100.0% | 2/0/0 |
| `path` | 100.0% | 100.0% | 2/0/0 |
| `sql` | 100.0% | 100.0% | 5/0/0 |
| `url` | 66.7% | 100.0% | 2/1/0 |

残っている誤り（隠さずに書く）:

- **偽陽性**: `clean/path-basename.ts:10` (`xss-res-send`)
- **偽陽性**: `clean/redirect-whitelist.ts:10` (`redirect-res`)

最終更新: 2026-10-08（`npm run bench` で再現可能）
<!-- BENCHMARK:END -->

測り方の定義:

- **適合率 (precision)** = 真陽性 / (真陽性 + 偽陽性) — 報告したうち本当に危険だった割合
- **再現率 (recall)** = 真陽性 / (真陽性 + 偽陰性) — 危険な箇所のうち報告できた割合
- 「安全」とラベルした箇所への検出も偽陽性として数える（サニタイザ理解の指標になる）

## 設定

プロジェクト直下に `.shirokuma.yml` を置くと、組み込みルールへ **追記** されます
（置き換えではありません）。書式の全文は
[docs/shirokuma.example.yml](docs/shirokuma.example.yml) にあります。

```yaml
rules:
  sources:
    - id: internal-ticket-header
      member: req.headers.x-internal-ticket
      kinds: [sql, html]

  sanitizers:
    # 第 1 引数がリテラルのときだけ有効（＝プレースホルダ用法）
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
      message: レポートへ未検証の HTML を埋め込んでいます
      taintedArgs: [1]   # 第 2 引数だけを検査する（0-based）

output:
  failOn: error
```

## GitHub Code Scanning との連携

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

`partialFingerprints` に検出 ID を入れているので、同じ指摘は
再実行しても「新規」ではなく「継続」として扱われます。

## 開発

```bash
npm install
npm run build        # dist へコンパイル
npm run typecheck    # 型検査（strict + noUncheckedIndexedAccess + exactOptionalPropertyTypes）
npm test             # 484 テスト
npm run bench        # 精度測定（reports/ へ出力）
npm run selfscan     # 自分自身をスキャンする（ドッグフーディング）
```

型検査は `strict` に加えて `noUncheckedIndexedAccess` と
`exactOptionalPropertyTypes` を有効にしています。配列やレコードの参照が
`T | undefined` になるため冗長に見えますが、「存在しないかもしれない値」を
無視した実装が混入するのを型で防げます。

## 既知の制限

正直に書きます。ここを隠すと、実際に使ったときに期待を裏切ります。

- **型情報を使わない。** 単一ファイルの AST だけを読みます。npm パッケージを
  またぐ伝播は追えません。`import` した関数の中身は解析対象外です。
- **フロー感度が限定的。** 分岐や例外による到達可能性は判定しません。
  `if (isAdmin) { db.query(sql) }` のような「実際には到達しない」経路も報告します。
- **ガード節を理解しない。** `ALLOWED.has(target) ? target : '/home'` のような
  許可リスト検証を無害化として認識しません（ベンチマークの偽陽性 1 件がこれです）。
- **文字列の内容を見ない。** `parseInt` の結果が数値であることは分かりますが、
  文字列が「安全な SQL」かどうかは判定しません。
- **`res.send` / `res.redirect` は警告レベル。** 到達した汚染を報告するため、
  HTML として解釈されない応答でも検出されます。
- **汚染解析は健全性を保証しない。** 見逃しは必ず存在します。
  適合率・再現率は上記ベンチマークの範囲での実測値であり、
  すべてのコードベースでの性能を約束するものではありません。

## ライセンス

MIT — [LICENSE](LICENSE)
