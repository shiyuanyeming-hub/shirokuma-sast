# アーキテクチャ

## 全体像

shirokuma-sast は「構文を読む層」と「意味を判定する層」を分離している。
汚染解析の正しさは 2 つの独立した判断に分解できる。

1. **値はどこからどこへ流れるか** — 構文とスコープから決まる。ルールに依存しない。
2. **その値は危険か** — 設定（ソース／サニタイザ／シンク）から決まる。構文に依存しない。

この 2 つを混ぜると、ルールを 1 つ足すたびにパーサを触ることになる。
本エンジンは混ぜない。

```text
                    ┌──────────────────────────────────────────┐
   TypeScript AST   │  src/ir/  —  構文からデータフローへ        │
   ───────────────▶ │  builder.ts / ast-helpers.ts / label.ts  │
                    │  ※ ルールを一切参照しない                  │
                    └────────────────────┬─────────────────────┘
                                         │ IRGraph（関数・ノード・辺・呼び出しサイト）
                                         ▼
                    ┌──────────────────────────────────────────┐
   .shirokuma.yml   │  src/rules/  —  ルールをグラフへ写像       │
   ───────────────▶ │  match.ts / builtin.ts / annotate.ts     │
                    │  ※ 構文木を走査しない（ResolvedExpression）│
                    └────────────────────┬─────────────────────┘
                                         │ AnnotatedGraph（source/sanitizer/sink 出現）
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │  src/analysis/  —  ワークリスト法         │
                    │  worklist.ts / solver.ts / summary.ts    │
                    │  ※ 検出の根拠（proof）を必ず組み立てる    │
                    └────────────────────┬─────────────────────┘
                                         │ Finding[]
                                         ▼
                    ┌──────────────────────────────────────────┐
                    │  src/reporters/  —  出力                  │
                    │  pretty / json / sarif / markdown        │
                    └──────────────────────────────────────────┘
```

各層は前の層の出力だけを知り、次の層を import しない。
そのため IR 構築はソルバ無しでテストでき、レポータはエンジン無しでテストできる
（`test/ir/`、`test/analysis/`、`test/reporters/` がそれぞれ独立している）。

## なぜ AST から直接解析しないのか

「AST を歩いて `req.query` を探し、見つけたら `db.query` を探す」実装は 200 行で書ける。
しかし次の 3 つで必ず破綻する。

| 破綻する入力 | 構文だけの実装 | 本エンジン |
| --- | --- | --- |
| `const a = req.query.x; const b = a; sink(b);` | 変数を追えない | データフロー辺で追跡 |
| `function f(x){ return x; } sink(f(req.query.x));` | 関数をまたげない | 呼び出し解決＋サマリ |
| `const s = escapeHtml(req.query.x); sink(s);` | サニタイザを知らない | 無害化タグの除去 |

そこで、まず **中間表現（IR）** へ落とす。IR は
`FlowNode`（値の発生点）と `FlowEdge`（値の移動）からなる有向グラフで、
「どの式がどの式へ流れ込むか」だけを表現する。

## IR が表現する 16 の伝播

`src/ir/contract.ts` に列挙し、`test/ir/builder.test.ts` の各テストで固定している。

| # | 形 | 例 |
| --- | --- | --- |
| 1 | 変数宣言 | `const x = tainted` |
| 2 | 再代入 | `x = tainted` |
| 3 | 文字列連結 | `'a' + tainted` |
| 4 | テンプレートリテラル | `` `a${tainted}b` `` |
| 5 | 配列・オブジェクト生成 | `[tainted]`, `{ k: tainted }` |
| 6 | プロパティ読み書き | `obj.k = tainted; sink(obj.k)` |
| 7 | 呼び出し引数 | `f(tainted)`（`argIndex` を記録） |
| 8 | 分割代入 | `const { a } = tainted` |
| 9 | スプレッド | `f(...tainted)`, `{ ...tainted }` |
| 10 | `return` 文 | `return tainted` |
| 11 | アロー式の暗黙 return | `x => x.body` |
| 12 | ローカル関数の解決 | `function f(){}; f(t)` |
| 13 | メソッド呼び出しの解決 | `this.m(t)`, `obj.m(t)` |
| 14 | クラス・getter | `class C { get g(){} }` |
| 15 | 高階関数 | `arr.map(t => sink(t))` |
| 16 | 引数 → 戻り値の連鎖 | `function id(x){return x}; sink(id(t))` |

### 宣言解決（前方参照）

IR 構築は 2 段階で進む。

1. **宣言の収集** — 関数・メソッド・仮引数・変数の「値ノード」を先に作る
2. **本体の走査** — 各式のノードと辺を作る

1 を先に行うのは、JavaScript の関数巻き上げと相互再帰に対応するためである。
`function a(){ b(); } function b(){ a(); }` では、`a` を走査する時点で
`b` がまだ登録されていなければ呼び出しを解決できない。

読み出しの解決は「その位置より前に**終わっている**直近の宣言」を優先する。
前方参照しか無い場合は最初の宣言へ結ぶ。仮引数の宣言位置は
**識別子そのもの**（型注釈を含まない範囲）で登録する。型注釈を含む範囲で登録すると
`function f(req: Request)` の `req` が一致せず、仮引数ノードが
`global` ノードで覆い隠される（実装中に実際に踏んだ不具合である）。

### 高階関数の配線

`arr.map(x => sink(x))` は「呼び出しの第 0 引数」と「コールバックの第 0 仮引数」を
結ばないと汚染が伝わらない。しかし IR の辺は値の移動だけを表すので、
この対応関係は辺にできない（コールバックは関数値なので「値」ではない）。

そこで IR 構築は `SolverHints.callbackLinks` として配線情報を別に返す。

```ts
interface CallbackLink {
  readonly callNodeId: string;
  readonly pairs: readonly { argNodeId: string; paramNodeId: string }[];
  readonly returnNodeId?: string;
}
```

解析エンジンは呼び出しノードへ汚染が到達したとき、`pairs` に従って
仮引数へも汚染を流す。型を別にしているのは、IR を「整形式のグラフ」に
保ちつつ、グラフでは表現できない意味づけを伝えるためである。

## 解析アルゴリズム

`src/analysis/worklist.ts` と `solver.ts` はワークリスト法で不動点を求める。

```text
すべてのソース出現ノードにトークンを投入
while ワークリストが空でない:
    トークン t をノード n から取り出す
    for n の各出力辺 e:
        到着点 m のトークン集合に t を加える
        加わった場合のみ m をワークリストへ戻す   ← 単調増加なので必ず停止する
```

### トークンの同一性

トークンは `(sourceId, kinds, nodeId, 経路)` を持つ。無限に増えないよう、
**同じ (sourceId, kinds, nodeId) のトークンは 1 つ**にまとめる。
経路は「最短で到達したときのもの」を保持する。これは
「なぜ危険か」を説明するには十分で、かつ状態数を有限に保つ。

### サニタイザ

サニタイザ出現ノードを通過するとき、**そのサニタイザが対応するタグだけ**を落とす。

- `escapeHtml` は `html` を落とすが `sql` は落とさない
- タグがすべて落ちたトークンは伝播を停止する

`validation: 'static-sql'` のサニタイザ（プレースホルダ付き `db.query`）は、
第 1 引数がリテラルのときだけ有効と判定する。`db.query(sql)` で
`sql` が変数なら **無効** とし、汚染は残す。ここを誤ると
「プレースホルダを使っているつもり」のコードを見逃す。

### 終了性

再帰・相互再帰では不動点まで反復する必要があるが、
`maxIterationsPerFunction` を超えたら打ち切り、
`stats.truncated` と診断に記録する。無限ループは起こさない。

### 根拠（proof）

検出は必ず経路を持つ。

```text
req.query.id            ← source
  └─ id                 ← propagate（代入）
      └─ 'SELECT …' + id ← propagate（連結）
          └─ sql        ← propagate（代入）
              └─ db.query(sql) ← sink
```

この経路があるから、レビュアは「なぜこの行が危険と判定されたか」を
エディタを開かずに理解できる。`codeFlows` として SARIF にも入る。

## ルール照合

`src/rules/match.ts` は `ResolvedExpression`（メンバ式・識別子・呼び出し名・
引数の形）だけを受け取る。構文木は受け取らない。
これによりルール照合のテストが構文に依存しない。

プロパティアクセスは **最長一致** を採る。
`req.query` がソースなら `req.query.id` もソースである。
`req.query.id` 用のルールが別にあれば、そちらが優先される。

## 決定性

同じ入力から同じ出力が得られることを、次の 3 点で担保している。

1. ファイル探索を辞書順に固定（`src/discovery.ts`）
2. ノード ID を構築順の連番にする（`<関数ID>#<連番>`）
3. レポータで再ソートしない。正準順序はエンジンが決める（ファイル → 行 → 列 → ruleId）

`PartialFingerprints` は検出 ID（`ruleId:file:line:column`）なので、
再実行しても GitHub 上で同じ指摘として扱われる。

## 依存関係の向き

```text
types.ts          ← すべての層が参照する（他の層を参照しない）
util/impl.ts      ← すべての層が参照する
ir/               ← types, util
rules/            ← types, ir
analysis/         ← types, rules(annotate の型のみ)
reporters/        ← types のみ
engine.ts         ← すべてを組み立てる
cli/              ← engine, reporters
```

`engine.ts` だけが全層を知る。層をまたぐ import を増やしたくなったら、
それは設計の匂いである（実際、レポータの `projectRoot` 推定は
循環 import を避けるため各ファイルに重複させている。10 行の重複と
循環依存なら、重複を選ぶ）。
