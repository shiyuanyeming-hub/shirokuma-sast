# 実行例: 脆弱な API を解析する

このディレクトリには、**意図的に脆弱な** Express 風のコードが入っています。
shirokuma-sast が何を検出し、何を検出しないかを手元で確認するための教材です。
実際に動かす必要はありません（実行しないでください）。

## 実行

リポジトリのルートで:

```bash
npm run build
node dist/cli/main.js scan examples/vulnerable-api --fail-on none
```

## この例で確かめられること

| ファイル | 期待される判定 | 何を示しているか |
| --- | --- | --- |
| `src/routes.ts` | 検出する | 変数と文字列連結を経由した SQL 注入 |
| `src/helpers.ts` | 検出する | 関数をまたいだ伝播（`buildQuery` の戻り値） |
| `src/command.ts` | 検出する | `exec` への到達と、`execFile` 配列引数との差 |
| `src/render.ts` | 検出する | `innerHTML` への未エスケープ代入 |
| `safe/routes.ts` | 検出しない | プレースホルダを使った正しい書き方 |
| `safe/render.ts` | 検出しない | `escapeHtml` を通した正しい書き方 |
| `safe/command.ts` | 検出しない | `execFile` に配列を渡す正しい書き方 |

「検出しない」ことも結果の一部です。安全なコードを報告しないことは、
危険なコードを見つけることと同じくらい重要です。

## proof を読む

検出結果には必ずソースからシンクまでの経路が付きます。

```
├─ source    src/routes.ts:6:14  req.query.id
├─ propagate src/routes.ts:6:9   id
├─ propagate src/routes.ts:7:15  'SELECT * FROM users WHERE id = ' + id
├─ propagate src/routes.ts:7:9   sql
└─ sink      src/routes.ts:8:3   db.query
```

この経路があるので、「本当に到達しうるのか」を確認するために
コードを読み直す必要がありません。これが SAST で最も時間を食う作業です。
