# ルールリファレンス

組み込みルールの規模:

| 種別 | 件数 |
| --- | --- |
| ソース（汚染の入口） | 47 |
| サニタイザ（無害化） | 34 |
| シンク（危険な操作） | 147 |
| 伝播規則（追加分） | 64 |
| 既定の除外パス | 12 |

シンクの重要度内訳: `error` 101 / `warning` 44 / `note` 2。

一覧はコマンドで確認できます。

```bash
shirokuma rules          # 人が読む形式
shirokuma rules --json   # 機械可読
```

---

## 1. ルールの書き方

ルールは「AST のどんな形に一致するか」を 3 つのキーで指定します。
`member` / `identifier` / `call` のうち **1 つ以上** が必要です。

```yaml
- id: my-rule            # 必須・一意
  member: db.rawQuery    # `a.b` 形式のメンバ式（ドット区切り）
  identifier: untrusted  # 単純な識別子（引数名・変数名）
  call: rawQuery         # 呼び出し名（レシーバを問わない）
  kinds: [sql]           # タグ。ソース・サニタイザ・シンクで意味が異なる
```

### `member` の一致規則

`member` は **メンバ式の完全一致** で照合します。ただし
**先頭が `.` で始まる場合は「末尾一致」** として扱われます。

| パターン | 一致する例 | 説明 |
| --- | --- | --- |
| `child_process.exec` | `child_process.exec(...)` | 完全一致 |
| `.innerHTML` | `node.innerHTML`、`el.innerHTML` | 末尾一致（レシーバを問わない） |
| `req.query` | `req.query`、`req.query.id`（最長一致） | 接頭辞としても一致 |

プロパティアクセスは **最も長く一致した規則** が採用されます。
`req.query` 用の規則と `req.query.id` 用の規則があれば、
`req.query.id` には後者が適用されます。

### タグ（`kinds`）の語彙

タグは「汚染の種類」を表し、サニタイザは **自分のタグだけ** を落とします。

| タグ | 意味 |
| --- | --- |
| `sql` | SQL 文に組み込まれると危険 |
| `html` | HTML として解釈されると危険 |
| `command` | シェルコマンドに組み込まれると危険 |
| `path` | ファイルパスに組み込まれると危険 |
| `code` | コードとして評価されると危険 |
| `nosql` | NoSQL のクエリ演算子に組み込まれると危険 |
| `url` | リダイレクト先・リクエスト先になると危険 |
| `header` | HTTP ヘッダに組み込まれると危険（CWE-113） |
| `unknown` | 種類が特定できていない（保守的にすべてのシンクへ流す） |

利用者入力のソースは既定で **9 種類すべてのタグ** を持ちます。
これは意図的な設計です。`req.query.x` が SQL に入るか HTML に入るかは
利用側のコードが決めることで、入口では分かりません。
サニタイザを通った時点でタグが絞られます。

---

## 2. ソース（47 種）

| 系統 | 例 |
| --- | --- |
| Express | `req.query` / `req.body` / `req.params` / `req.headers` / `req.cookies` / `req.url` / `req.originalUrl` / `req.path` |
| Koa | `ctx.query` / `ctx.querystring` / `ctx.params` / `ctx.headers` / `ctx.request.body` / `ctx.cookies.get()` |
| Fastify / 汎用 | `request.query` / `request.body` / `request.params` / `request.headers` / `request.cookies` / `request.raw.url` |
| AWS Lambda | `event.queryStringParameters` / `event.body` / `event.pathParameters` / `event.headers` |
| ブラウザ | `location.search` / `location.hash` / `location.href` / `window.name` / `document.URL` / `document.referrer` / `document.cookie` / `document.baseURI` |
| Node | `process.argv` / `process.env` |
| レガシー API | `request.getParameter()` |
| 関数引数 | `req` / `request` という名前の引数（フレームワーク非依存の保險） |

`req` / `request` を引数名で拾う規則は、Express 以外のフレームワークや
自作の HTTP ハンドラを取りこぼさないための保険です。過剰検出とのトレードオフですが、
「引数名が `req`」という条件は実務上ほぼ確実にリクエストです。

## 3. サニタイザ（34 種）

サニタイザは `kinds` に挙げたタグだけを落とします。

| 系統 | 例 | 落とすタグ |
| --- | --- | --- |
| HTML エスケープ | `escapeHtml` / `escape-html` / `he.encode` / `he.escape` / `xss()` / `DOMPurify.sanitize` / `sanitize-html` | `html` |
| URL エンコード | `encodeURIComponent` | `html`, `url` |
| SQL プレースホルダ | `db.query` / `connection.query` / `pool.query` / `sequelize.query` / `knex.raw` | `sql` |
| SQL エスケープ | `mysql.escape` | `sql` |
| シェル引用 | `shellQuote` / `shellEscape` | `command` |
| 配列引数 | `execFile` / `execFileSync`（配列を渡す場合） | `command` |
| パス | `path.basename` / `sanitize-filename` / `filenamify` | `path` |
| （注）`path.join` はサニタイザではない | `path.join(base, name)` は `..` を正規化するだけで拒否しないため、`../../etc/passwd` が通り抜ける | — |
| NoSQL | `mongo-sanitize` / `sanitizeFilter` | `nosql` |
| リダイレクト | `sanitizeUrl` | `url` |
| 数値強制 | `parseInt` / `Number.parseInt` / `parseFloat` / `Number` | `sql`, `html`, `command`, `path`, `code`, `nosql`, `url` |

### 用法の検証（`validation`）

「サニタイザを呼んでいるか」だけでは不十分です。
呼び方によっては無害化できていないため、用法まで検証します。

| `validation` | 意味 | 有効な例 | 無効な例 |
| --- | --- | --- | --- |
| `static-sql` | プレースホルダ用法か | `db.query('... = $1', [id])` | `db.query(sqlVar)` ← **無効** |
| `constant-argument` | 指定位置がリテラルか | `execFile('ping', ['-c','1',host])` | `execFile(cmdVar, args)` ← **無効** |
| `none` | 常に有効 | `escapeHtml(x)` | — |

`static-sql` の判定は「第 1 引数が文字列リテラル、または補間を含まないテンプレートリテラル」です。
`db.query(sql)` で `sql` が変数の場合、**サニタイザとして無効** と判定し、
汚染はシンクまで到達します。これが本エンジンで最も重要な判定の 1 つで、
「プレースホルダを使っているつもり」のコードを見逃さないための仕組みです。

`constant-argument` は `execFile` の配列引数に使っています。
`execFile('ping', ['-c', '1', host])` はシェルを経由しないため安全ですが、
第 1 引数（実行ファイル）が変数であれば別のコマンドを実行できてしまうため、
その場合は無効と判定します。

### パス正規化はサニタイザにしない

`path.join` / `path.resolve` は **サニタイザとして登録していません**。
基準ディレクトリが定数であっても、`..` は「正規化される」だけで拒否されないためです。

```ts
const name = req.query.name;                      // 攻撃者が完全に制御する
const target = path.join('/srv/files', name);      // name = '../../etc/passwd' で脱出できる
fs.readFileSync(target, 'utf8');                   // ← CWE-22 として検出する（正しい）
```

`path.join('/srv/files', '../../etc/passwd')` は `/etc/passwd` を返します。
したがって `path.join` はタグを落とさず、伝播規則としてだけ登録しています
（`path` タグをシンクまで運ぶ）。

実際にパストラバーサルを防げるのは、ディレクトリ成分を落とす `path.basename` と、
ファイル名として正規化する `sanitizeFilename` / `filenamify` です。

```ts
const safeName = path.basename(req.query.name);    // `../../etc/passwd` → `passwd`
fs.readFileSync(path.join('/srv/files', safeName)); // 検出しない（basename が path タグを落とす）
```

許可リスト方式（`resolved.startsWith(BASE)` を検証する等）は制御フローに依存するため、
パターンマッチだけでは判定できません。誤って「安全」と判定するより、
検出する側に倒しています。

### 過剰検出を減らす設計

サニタイザは「タグ単位」で働きます。したがって:

```ts
const safe = escapeHtml(req.query.comment);   // html タグが落ちる
db.query('... = ' + safe);                     // sql タグは残っている → 検出（正しい）
```

```ts
const id = Number.parseInt(req.query.id, 10);  // 数値化 → 全タグが落ちる
db.query('SELECT * FROM t WHERE id = ' + id);  // 検出しない（数値なので安全）
```

2 つ目を検出しないのは正しい挙動です。数値に変換された値は
SQL インジェクションを起こせません。

## 4. シンク（147 種）

| CWE | 件数 | 主な対象 |
| --- | --- | --- |
| CWE-22 パストラバーサル | 39 | `fs.readFile` / `readFileSync` / `createReadStream` / `writeFile` / `unlink` / `mkdir` / `readdir` / `stat` / `open` / `copyFile` / `rename` / `chmod` / `symlink` / `realpath` ほか、`res.sendFile` / `res.download` |
| CWE-918 SSRF | 21 | `fetch` / `axios.*` / `http.request` / `https.get` / `got` / `superagent` / `request` / `undici` |
| CWE-943 NoSQL | 17 | `find` / `findOne` / `findById` / `findOneAndUpdate` / `updateMany` / `deleteOne` / `aggregate` / `$where` / `mapReduce` / `bulkWrite` |
| CWE-79 XSS | 15 | `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write` / `dangerouslySetInnerHTML` / `res.send` / `res.write` / `res.render` / `ctx.body` |
| CWE-89 SQL | 11 | `query` / `execute` / `raw` / `prepare` / `queryRaw` / `$queryRawUnsafe` / `knex.raw` / `db.exec` |
| CWE-78 OS コマンド | 11 | `exec` / `execSync` / `execFile` / `execFileSync` / `spawn` / `spawnSync` / `fork` / `shell.exec` |
| CWE-601 オープンリダイレクト | 11 | `res.redirect` / `location.assign` / `location.replace` / `window.open` |
| CWE-94 コード注入 | 10 | `eval` / `Function` / `vm.runInNewContext` / `vm.runInThisContext` / `setTimeout`（文字列） |
| CWE-113 ヘッダ注入 | 7 | `res.setHeader` / `res.header` / `res.cookie` / `res.location` |
| CWE-502 安全でないデシリアライズ | 1 | `serialize-javascript` 相当の `deserialize` |
| CWE-1336 テンプレート注入 | 4 | テンプレートエンジンのコンパイル API |

### 重要度の付け方

| 重要度 | 意味 | 例 |
| --- | --- | --- |
| `error` | 到達すれば即座に脆弱性 | `eval`、`exec`、文字列連結の SQL クエリ |
| `warning` | 到達しても文脈次第で無害 | `res.send`（HTML でない応答もある）、`res.redirect`（固定先なら無害） |
| `note` | 参考情報 | 動的プロパティ、`res.render` のテンプレート名 |

重要度は CVSS ではありません。「修正の優先順位」を伝えるラベルです。
数値スコアをでっち上げると、かえって判断を誤らせると考えています。

### `taintedArgs` による引数の限定

シンクの全引数を検査すると過剰検出が増えます。
`taintedArgs`（0-based）で検査する引数を限定できます。

```yaml
- id: custom-report-render
  member: report.render
  kinds: [html]
  severity: warning
  message: 未検証の HTML を埋め込んでいます
  taintedArgs: [1]   # 第 2 引数だけを検査する
```

**プロパティ代入のシンク**（`member: '.innerHTML'` など）は引数を持たないため、
`taintedArgs` は無視され、代入値そのものを検査します。

## 5. 伝播規則（64 種）

組み込みの伝播（代入・連結・テンプレート・分割代入・スプレッド・
引数・戻り値・高階関数）に加えて、値をそのまま素通しする
ユーティリティ関数を登録しています。

```yaml
propagators:
  - call: passThrough
  - member: utils.identity
  - member: lodash.cloneDeep
```

伝播規則を登録すると、その呼び出しを **サニタイザでも未知の関数でもなく
「素通し」** として扱います。未登録の関数呼び出しは、
戻り値に汚染が残るかどうかを判断できないため、
保守的に「引数が戻り値へ流れる」可能性を残しません
（＝サニタイザとして振る舞う）。

## 6. 既定の除外パス（12 種）

生成物と依存を既定で除外します。

```text
node_modules  dist  build  out  coverage  .git  .next  .nuxt  .svelte-kit
vendor  .venv  venv
```

加えて `**/*.d.ts`（型定義のみ）と `**/*.min.js` / `**/*.bundle.js`
（圧縮済み）を除外します。
設定の `ignorePaths` は **置換** です（明示指定があれば既定を捨てます）。

---

## 7. ルールを追加するときの指針

1. **まず過剰検出を疑う。** `call: query` のような一般的な名前は、
   無関係な API にも一致します。`member: db.query` のように
   レシーバを特定できないか検討してください。
2. **`kinds` は最小限にする。** タグを増やすほどサニタイザで落ちにくくなり、
   過剰検出が増えます。
3. **用法まで検証できないか考える。** プレースホルダのように
   「正しい使い方」がある API は `validation` を付けてください。
4. **ベンチマークで効果を測る。** ルールを足したら `npm run bench` を実行し、
   適合率・再現率の変化を確認してください。教師データを増やす場合は
   `benchmarks/manifest.json` に行番号付きで追記します。
