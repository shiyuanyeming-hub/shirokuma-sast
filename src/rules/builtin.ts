/**
 * 組み込みルールセット — 既定のソース／サニタイザ／シンク／伝播規則。
 *
 * Node.js / TypeScript の Web アプリで実際に使われる API を対象に、OWASP Top 10 の
 * インジェクション系（CWE-89 / 79 / 78 / 22 / 94 / 943 / 601 / 918 ほか）を既定で検出する。
 *
 * ## タグ語彙
 * `kinds` は「その値が何として危険になりうるか」を表す。語彙はコントラクトで固定されており、
 * ここでは `code` / `command` / `header` / `html` / `nosql` / `path` / `sql` / `unknown` / `url`
 * のみを使う。配列は常に **昇順（コード単位）** で並べ、出力の決定性を保つ。
 *
 * ## 方針
 * - ソースは保守的に（過大近似で）タグ付けする。タグが広いほど検出漏れは減り、
 *   誤検出は各サニタイザ／シンクの精度で抑える。
 * - 呼び出しシンクは可能な限り `call` を併記し、呼び出し式にのみ一致させる
 *   （プロパティ読み取りを誤ってシンク扱いしないため）。
 * - プロパティ代入が攻撃面になるもの（`el.innerHTML` など）は先頭 `.` の接尾辞パターンで表す。
 */
import type {
  AnalysisConfig,
  OutputConfig,
  PatternSpec,
  SanitizerSpec,
  SinkSpec,
  SourceSpec,
} from '../types.js';

// ---------------------------------------------------------------------------
// 既定の解析・出力設定
// ---------------------------------------------------------------------------

/** 既定の解析パラメータ。深い呼び出し文脈は追わず、反復上限で必ず停止させる。 */
export const DEFAULT_ANALYSIS: AnalysisConfig = {
  maxCallDepth: 3,
  maxIterations: 200,
  dedupe: true,
};

/** 既定の出力設定。標準出力へ pretty、CI ゲートは `error` のみ失敗扱い。 */
export const DEFAULT_OUTPUT: OutputConfig = {
  format: 'pretty',
  failOn: 'error',
};

/** 既定の除外パス。依存物・生成物・カバレッジを解析対象から外す。 */
export const DEFAULT_IGNORE_PATHS: readonly string[] = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/out/**',
  '**/coverage/**',
  '**/.git/**',
  '**/.next/**',
  '**/.nuxt/**',
  '**/vendor/**',
  '**/*.min.js',
  '**/*.d.ts',
  '**/*.js.map',
];

// ---------------------------------------------------------------------------
// タグ集合（決定性のため常に昇順）
// ---------------------------------------------------------------------------

/** HTTP リクエスト全体（query / body / params / headers / cookies）のタグ。 */
const REQUEST_KINDS: readonly string[] = ['code', 'command', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url'];

/** ブラウザ側（DOM / location / document）のタグ。シェル実行は想定しないため `command` を含めない。 */
const BROWSER_KINDS: readonly string[] = ['code', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url'];

/** 実行環境（`process.argv` / `process.env`）のタグ。 */
const ENVIRONMENT_KINDS: readonly string[] = ['code', 'command', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url'];

/** URL 文字列として危険になりうるタグ。 */
const URL_KINDS: readonly string[] = ['html', 'path', 'unknown', 'url'];

/** 数値強制（`parseInt` など）で無害化できるタグ。 */
const NUMERIC_SAFE_KINDS: readonly string[] = ['code', 'command', 'html', 'nosql', 'path', 'sql', 'url'];

// ---------------------------------------------------------------------------
// ソース
// ---------------------------------------------------------------------------

/**
 * 組み込みソース。Express / Koa / Fastify / NestJS / 生 `http` / Lambda / DOM / Node 環境を網羅する。
 *
 * `member` は接頭辞一致なので、`req.query` を宣言すれば `req.query.id` も自動的にソースになる。
 */
export const BUILTIN_SOURCES: readonly SourceSpec[] = [
  // --- Express / Connect（`req`） ---
  {
    id: 'express-query',
    member: 'req.query',
    kinds: REQUEST_KINDS,
    description: 'Express: クエリ文字列（`?a=b`）由来の値。',
  },
  {
    id: 'express-body',
    member: 'req.body',
    kinds: REQUEST_KINDS,
    description: 'Express: リクエストボディ（JSON / form）由来の値。',
  },
  {
    id: 'express-params',
    member: 'req.params',
    kinds: REQUEST_KINDS,
    description: 'Express: パスパラメータ（`/users/:id`）由来の値。',
  },
  {
    id: 'express-headers',
    member: 'req.headers',
    kinds: REQUEST_KINDS,
    description: 'Express: リクエストヘッダ由来の値。',
  },
  {
    id: 'express-cookies',
    member: 'req.cookies',
    kinds: REQUEST_KINDS,
    description: 'Express: Cookie 由来の値。',
  },
  {
    id: 'express-param-call',
    member: 'req.param',
    kinds: REQUEST_KINDS,
    description: 'Express: `req.param(name)` の戻り値。',
  },
  {
    id: 'express-get-header',
    member: 'req.get',
    kinds: REQUEST_KINDS,
    description: 'Express: `req.get(name)` / `req.header(name)` の戻り値。',
  },
  {
    id: 'express-header-call',
    member: 'req.header',
    kinds: REQUEST_KINDS,
    description: 'Express: `req.header(name)` の戻り値。',
  },
  {
    id: 'express-url',
    member: 'req.url',
    kinds: URL_KINDS,
    description: 'Express: リクエスト URL（パス + クエリ）。',
  },
  {
    id: 'express-original-url',
    member: 'req.originalUrl',
    kinds: URL_KINDS,
    description: 'Express: 書き換え前のリクエスト URL。',
  },
  {
    id: 'express-path',
    member: 'req.path',
    kinds: URL_KINDS,
    description: 'Express: リクエストパス部分。',
  },
  {
    id: 'express-request-identifier',
    identifier: 'req',
    kinds: REQUEST_KINDS,
    description: 'Express: 引数 `req` そのもの（プロパティ個別の宣言を補完する）。',
  },
  {
    id: 'express-request-args',
    identifier: 'request',
    kinds: REQUEST_KINDS,
    description: 'Fastify / Koa / NestJS: 引数 `request` そのもの。',
  },

  // --- Koa（`ctx`） ---
  {
    id: 'koa-query',
    member: 'ctx.query',
    kinds: REQUEST_KINDS,
    description: 'Koa: `ctx.query` の値。',
  },
  {
    id: 'koa-querystring',
    member: 'ctx.querystring',
    kinds: URL_KINDS,
    description: 'Koa: 生のクエリ文字列。',
  },
  {
    id: 'koa-params',
    member: 'ctx.params',
    kinds: REQUEST_KINDS,
    description: 'Koa: ルータのパスパラメータ。',
  },
  {
    id: 'koa-headers',
    member: 'ctx.headers',
    kinds: REQUEST_KINDS,
    description: 'Koa: リクエストヘッダ。',
  },
  {
    id: 'koa-request-body',
    member: 'ctx.request.body',
    kinds: REQUEST_KINDS,
    description: 'Koa: リクエストボディ。',
  },
  {
    id: 'koa-request-query',
    member: 'ctx.request.query',
    kinds: REQUEST_KINDS,
    description: 'Koa: `ctx.request.query` の値。',
  },
  {
    id: 'koa-cookies-get',
    member: 'ctx.cookies.get',
    kinds: REQUEST_KINDS,
    description: 'Koa: `ctx.cookies.get(name)` の戻り値。',
  },
  {
    id: 'koa-url',
    member: 'ctx.url',
    kinds: URL_KINDS,
    description: 'Koa: リクエスト URL。',
  },
  {
    id: 'koa-original-url',
    member: 'ctx.originalUrl',
    kinds: URL_KINDS,
    description: 'Koa: 書き換え前のリクエスト URL。',
  },

  // --- Fastify / NestJS（`request`） ---
  {
    id: 'request-query',
    member: 'request.query',
    kinds: REQUEST_KINDS,
    description: 'Fastify / NestJS: `request.query` の値。',
  },
  {
    id: 'request-body',
    member: 'request.body',
    kinds: REQUEST_KINDS,
    description: 'Fastify / NestJS: `request.body` の値。',
  },
  {
    id: 'request-params',
    member: 'request.params',
    kinds: REQUEST_KINDS,
    description: 'Fastify / NestJS: `request.params` の値。',
  },
  {
    id: 'request-headers',
    member: 'request.headers',
    kinds: REQUEST_KINDS,
    description: 'Fastify / NestJS: `request.headers` の値。',
  },
  {
    id: 'request-cookies',
    member: 'request.cookies',
    kinds: REQUEST_KINDS,
    description: 'Fastify / NestJS: `request.cookies` の値。',
  },
  {
    id: 'request-url',
    member: 'request.url',
    kinds: URL_KINDS,
    description: 'Fastify / 生 http: `request.url` の値。',
  },
  {
    id: 'request-raw-url',
    member: 'request.raw.url',
    kinds: URL_KINDS,
    description: 'Fastify: `request.raw.url` の値。',
  },

  // --- AWS Lambda / API Gateway ---
  {
    id: 'lambda-query-string',
    member: 'event.queryStringParameters',
    kinds: REQUEST_KINDS,
    description: 'Lambda: API Gateway のクエリパラメータ。',
  },
  {
    id: 'lambda-body',
    member: 'event.body',
    kinds: REQUEST_KINDS,
    description: 'Lambda: API Gateway のリクエストボディ。',
  },
  {
    id: 'lambda-path-parameters',
    member: 'event.pathParameters',
    kinds: REQUEST_KINDS,
    description: 'Lambda: API Gateway のパスパラメータ。',
  },
  {
    id: 'lambda-headers',
    member: 'event.headers',
    kinds: REQUEST_KINDS,
    description: 'Lambda: API Gateway のヘッダ。',
  },

  // --- レガシー API ---
  {
    id: 'legacy-get-parameter',
    call: 'getParameter',
    kinds: REQUEST_KINDS,
    description: '`getParameter(name)` のようなフレームワーク薄いラッパー。',
  },

  // --- ブラウザ（DOM / location） ---
  {
    id: 'location-search',
    member: 'location.search',
    kinds: BROWSER_KINDS,
    description: 'DOM: `location.search`（クエリ文字列）。',
  },
  {
    id: 'location-hash',
    member: 'location.hash',
    kinds: BROWSER_KINDS,
    description: 'DOM: `location.hash`（フラグメント）。',
  },
  {
    id: 'location-href',
    member: 'location.href',
    kinds: BROWSER_KINDS,
    description: 'DOM: `location.href`。',
  },
  {
    id: 'location-pathname',
    member: 'location.pathname',
    kinds: BROWSER_KINDS,
    description: 'DOM: `location.pathname`。',
  },
  {
    id: 'window-location',
    member: 'window.location',
    kinds: BROWSER_KINDS,
    description: 'DOM: `window.location`（配下のプロパティを含む）。',
  },
  {
    id: 'document-location',
    member: 'document.location',
    kinds: BROWSER_KINDS,
    description: 'DOM: `document.location`。',
  },
  {
    id: 'window-name',
    member: 'window.name',
    kinds: BROWSER_KINDS,
    description: 'DOM: `window.name`（クロスオリジンでも保持される）。',
  },
  {
    id: 'document-url',
    member: 'document.URL',
    kinds: BROWSER_KINDS,
    description: 'DOM: `document.URL`。',
  },
  {
    id: 'document-referrer',
    member: 'document.referrer',
    kinds: BROWSER_KINDS,
    description: 'DOM: `document.referrer`。',
  },
  {
    id: 'document-cookie',
    member: 'document.cookie',
    kinds: BROWSER_KINDS,
    description: 'DOM: `document.cookie`。',
  },
  {
    id: 'document-base-uri',
    member: 'document.baseURI',
    kinds: BROWSER_KINDS,
    description: 'DOM: `document.baseURI`。',
  },

  // --- Node 実行環境 ---
  {
    id: 'process-argv',
    member: 'process.argv',
    kinds: ENVIRONMENT_KINDS,
    description: 'Node: コマンドライン引数。',
  },
  {
    id: 'process-env',
    member: 'process.env',
    kinds: ENVIRONMENT_KINDS,
    description: 'Node: 環境変数（デプロイ経路によっては外部制御されうる）。',
  },
] satisfies readonly SourceSpec[];

// ---------------------------------------------------------------------------
// サニタイザ
// ---------------------------------------------------------------------------

/**
 * 組み込みサニタイザ。
 *
 * `validation` は「その呼び出しが本当に無害化しているか」の追加検証であり、
 * 失敗した場合はサニタイザ出現が `valid: false` となって汚染が残る。
 * - `static-sql`: 第 1 引数が文字列リテラル／補間なしテンプレートのときだけ有効。
 * - `constant-argument`: 第 1 引数が定数のときだけ有効（許可リストの基準ディレクトリなど）。
 * - `none`: 常に有効。
 */
export const BUILTIN_SANITIZERS: readonly SanitizerSpec[] = [
  // --- SQL: プレースホルダ用法（`db.query('... WHERE id = ?', [id])`） ---
  {
    id: 'sql-db-query',
    member: 'db.query',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `db.query(sql, params)`。',
  },
  {
    id: 'sql-connection-query',
    member: 'connection.query',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `connection.query`。',
  },
  {
    id: 'sql-pool-query',
    member: 'pool.query',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `pool.query`。',
  },
  {
    id: 'sql-client-query',
    member: 'client.query',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `client.query`。',
  },
  {
    id: 'sql-conn-query',
    member: 'conn.query',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `conn.query`。',
  },
  {
    id: 'sql-db-execute',
    member: 'db.execute',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `db.execute`。',
  },
  {
    id: 'sql-connection-execute',
    member: 'connection.execute',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `connection.execute`。',
  },
  {
    id: 'sql-pool-execute',
    member: 'pool.execute',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ化された `pool.execute`。',
  },
  {
    id: 'sql-sequelize-query',
    member: 'sequelize.query',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'プレースホルダ（`:name` / `?`）を使った `sequelize.query`。',
  },
  {
    id: 'sql-knex-raw',
    member: 'knex.raw',
    kinds: ['sql'],
    validation: 'static-sql',
    description: 'バインディング（`??` / `?`）を使った `knex.raw`。',
  },
  {
    id: 'sql-mysql-escape',
    member: 'mysql.escape',
    kinds: ['sql'],
    validation: 'none',
    description: '`mysql.escape(value)` による文字列エスケープ（プレースホルダより弱い）。',
  },

  // --- HTML ---
  {
    id: 'html-escape-html',
    call: 'escapeHtml',
    kinds: ['html'],
    validation: 'none',
    description: '`escapeHtml(value)` による HTML エスケープ。',
  },
  {
    id: 'html-escape',
    call: 'escape',
    kinds: ['html'],
    validation: 'none',
    description: 'グローバル `escape(value)` によるエスケープ。',
  },
  {
    id: 'html-he-encode',
    member: 'he.encode',
    kinds: ['html'],
    validation: 'none',
    description: '`he.encode(value)` による HTML エンティティ変換。',
  },
  {
    id: 'html-he-escape',
    member: 'he.escape',
    kinds: ['html'],
    validation: 'none',
    description: '`he.escape(value)` による HTML エスケープ。',
  },
  {
    id: 'html-dompurify-sanitize',
    member: 'DOMPurify.sanitize',
    kinds: ['html'],
    validation: 'none',
    description: '`DOMPurify.sanitize(html)` によるサニタイズ。',
  },
  {
    id: 'html-sanitize-html',
    call: 'sanitizeHtml',
    kinds: ['html'],
    validation: 'none',
    description: '`sanitize-html` によるサニタイズ。',
  },
  {
    id: 'html-xss',
    call: 'xss',
    kinds: ['html'],
    validation: 'none',
    description: '`xss(value)` によるサニタイズ。',
  },
  {
    id: 'html-encode-uri-component',
    call: 'encodeURIComponent',
    kinds: ['html'],
    validation: 'none',
    description: '`encodeURIComponent(value)`（HTML 文字もエスケープされる）。',
  },

  // --- コマンド ---
  {
    id: 'command-shell-quote',
    call: 'shellQuote',
    kinds: ['command'],
    validation: 'none',
    description: '`shellQuote(arg)` によるシェル引数のクォート。',
  },
  {
    id: 'command-shell-escape',
    call: 'shellEscape',
    kinds: ['command'],
    validation: 'none',
    description: '`shellEscape(arg)` によるシェル引数のエスケープ。',
  },
  {
    id: 'command-exec-file-constant',
    member: 'child_process.execFile',
    kinds: ['command'],
    validation: 'constant-argument',
    description: '実行ファイルが定数の `execFile`（シェルを経由しないため引数は安全）。',
  },
  {
    id: 'command-exec-file-sync-constant',
    member: 'child_process.execFileSync',
    kinds: ['command'],
    validation: 'constant-argument',
    description: '実行ファイルが定数の `execFileSync`。',
  },

  // --- パス ---
  // 注意: `path.join` / `path.resolve` は **サニタイザにしない**。
  // 基準ディレクトリが定数でも `..` は正規化されるだけで拒否されないため、
  // `path.join('/srv/files', name)` は `name = '../../etc/passwd'` で脱出できてしまう。
  // 実際に無害化できるのはディレクトリ成分を落とす `path.basename` と、
  // ファイル名として正規化する `sanitizeFilename` / `filenamify` だけである
  // （`fs.readFileSync(path.join('/srv/files', req.query.name))` は検出されなければならない）。
  {
    id: 'path-basename',
    member: 'path.basename',
    kinds: ['path'],
    validation: 'none',
    description: '`path.basename(value)` によるディレクトリ成分の除去。',
  },
  {
    id: 'path-sanitize-filename',
    call: 'sanitizeFilename',
    kinds: ['path'],
    validation: 'none',
    description: '`sanitizeFilename(value)` によるファイル名の正規化。',
  },
  {
    id: 'path-filenamify',
    call: 'filenamify',
    kinds: ['path'],
    validation: 'none',
    description: '`filenamify(value)` による安全なファイル名への変換。',
  },

  // --- NoSQL ---
  {
    id: 'nosql-mongo-sanitize',
    member: 'mongoSanitize.sanitize',
    kinds: ['nosql'],
    validation: 'none',
    description: '`mongoSanitize.sanitize(filter)` による `$` 演算子の除去。',
  },
  {
    id: 'nosql-sanitize-filter',
    call: 'sanitizeFilter',
    kinds: ['nosql'],
    validation: 'none',
    description: 'Mongoose `sanitizeFilter(filter)` による演算子注入の防止。',
  },

  // --- URL ---
  {
    id: 'url-sanitize-url',
    call: 'sanitizeUrl',
    kinds: ['url'],
    validation: 'none',
    description: '`sanitizeUrl(value)` による URL の正規化・検証。',
  },

  // --- 数値強制（あらゆる文字列インジェクションを無効化する） ---
  {
    id: 'coerce-parse-int',
    call: 'parseInt',
    kinds: NUMERIC_SAFE_KINDS,
    validation: 'none',
    description: '`parseInt(value, 10)` による数値化。',
  },
  {
    id: 'coerce-number-parse-int',
    member: 'Number.parseInt',
    kinds: NUMERIC_SAFE_KINDS,
    validation: 'none',
    description: '`Number.parseInt(value, 10)` による数値化。',
  },
  {
    id: 'coerce-parse-float',
    call: 'parseFloat',
    kinds: NUMERIC_SAFE_KINDS,
    validation: 'none',
    description: '`parseFloat(value)` による数値化。',
  },
  {
    id: 'coerce-number-parse-float',
    member: 'Number.parseFloat',
    kinds: NUMERIC_SAFE_KINDS,
    validation: 'none',
    description: '`Number.parseFloat(value)` による数値化。',
  },
  {
    id: 'coerce-number',
    call: 'Number',
    kinds: NUMERIC_SAFE_KINDS,
    validation: 'none',
    description: '`Number(value)` による数値化。',
  },
] satisfies readonly SanitizerSpec[];

// ---------------------------------------------------------------------------
// シンク（ヘルパー）
// ---------------------------------------------------------------------------

/** パターン指定と共通項目から `SinkSpec` を組み立てる。`exactOptionalPropertyTypes` 対応。 */
function withPattern(
  pattern: { readonly member?: string; readonly identifier?: string; readonly call?: string },
  rest: Omit<SinkSpec, 'member' | 'identifier' | 'call'>,
): SinkSpec {
  const { member, identifier, call } = pattern;
  return {
    ...rest,
    ...(member !== undefined ? { member } : {}),
    ...(identifier !== undefined ? { identifier } : {}),
    ...(call !== undefined ? { call } : {}),
  };
}

/** SQL インジェクション（CWE-89）の共通助言。 */
const SQL_ADVICE = 'SQL 文へ値を連結せず、プレースホルダ（`?` / `$1` / `:name`）とバインド引数を使ってください。';

/** XSS（CWE-79）の共通助言。 */
const XSS_ADVICE = '文脈に応じたエスケープ（HTML / 属性 / URL / JS）を行い、可能ならテンプレートエンジンの自動エスケープを使ってください。';

/** OS コマンドインジェクション（CWE-78）の共通助言。 */
const COMMAND_ADVICE = '`exec` 系ではなく `execFile` / `spawn` に配列引数を渡し、シェルを経由しないでください。';

/** パストラバーサル（CWE-22）の共通助言。 */
const PATH_ADVICE = '`path.basename` などでファイル名だけを取り出し、解決後のパスが許可ディレクトリ配下にあることを検証してください。';

/** コードインジェクション（CWE-94）の共通助言。 */
const CODE_ADVICE = '外部入力を動的評価しないでください。必要な場合は許可リスト方式で値を検証し、`vm` は使わないでください。';

/** NoSQL インジェクション（CWE-943）の共通助言。 */
const NOSQL_ADVICE = 'クエリ条件へ外部オブジェクトをそのまま渡さず、キーを検証して `$` 演算子を除去してください。';

/** オープンリダイレクト（CWE-601）の共通助言。 */
const REDIRECT_ADVICE = 'リダイレクト先は許可リストで検証し、相対パスのみを許可してください。';

/** SSRF（CWE-918）の共通助言。 */
const SSRF_ADVICE = 'URL はスキーム・ホストを許可リストで検証し、内部アドレス（127.0.0.1 / 169.254.169.254 等）への到達を拒否してください。';

/** ヘッダインジェクション（CWE-113）の共通助言。 */
const HEADER_ADVICE = 'ヘッダ値から改行（CR / LF）を除去し、許可された文字種のみを許可してください。';

/** SQL シンクを作る。 */
function sqlSink(id: string, pattern: { readonly member?: string; readonly call?: string }, api: string): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['sql'],
    severity: 'error',
    taintedArgs: [0],
    cwe: ['CWE-89'],
    message: `${api} へ外部入力が到達しています（SQL インジェクション）`,
    advice: SQL_ADVICE,
  });
}

/**
 * XSS シンク（呼び出し）を作る。
 *
 * `api` には「`res.send()`」のような呼び出し表記だけを渡すこと。
 * 「〜への代入」のような日本語の説明を渡すと「〜への代入 へ…」という文になってしまうため、
 * プロパティ代入のシンクには `xssAssignmentSink` を使う。
 */
function xssSink(
  id: string,
  pattern: { readonly member?: string; readonly call?: string },
  api: string,
  severity: 'error' | 'warning' = 'error',
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['html'],
    severity,
    taintedArgs: [0],
    cwe: ['CWE-79'],
    message: `${api} へ未エスケープの外部入力が到達しています（クロスサイトスクリプティング）`,
    advice: XSS_ADVICE,
  });
}

/**
 * XSS シンク（プロパティ代入）を作る。
 *
 * `el.innerHTML = value` のようなプロパティ代入は「到達しています」ではなく
 * 「代入しています」と書く（`xssSink` に「〜への代入」を渡すと日本語が壊れるため）。
 */
function xssAssignmentSink(
  id: string,
  pattern: { readonly member?: string },
  target: string,
  severity: 'error' | 'warning' = 'error',
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['html'],
    severity,
    taintedArgs: [0],
    cwe: ['CWE-79'],
    message: `${target} に未エスケープの外部入力を代入しています（クロスサイトスクリプティング）`,
    advice: XSS_ADVICE,
  });
}

/** OS コマンドシンクを作る。 */
function commandSink(
  id: string,
  pattern: { readonly member?: string; readonly call?: string },
  api: string,
  taintedArgs: readonly number[] = [0],
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['command'],
    severity: 'error',
    taintedArgs,
    cwe: ['CWE-78'],
    message: `${api} へ外部入力が到達しています（OS コマンドインジェクション）`,
    advice: COMMAND_ADVICE,
  });
}

/** パストラバーサルシンクを作る。 */
function pathSink(id: string, pattern: { readonly member?: string; readonly call?: string }, api: string, severity: 'error' | 'warning' = 'error'): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['path'],
    severity,
    taintedArgs: [0],
    cwe: ['CWE-22'],
    message: `${api} へ外部入力が到達しています（パストラバーサル）`,
    advice: PATH_ADVICE,
  });
}

/** コードインジェクションシンクを作る。 */
function codeSink(
  id: string,
  pattern: { readonly member?: string; readonly call?: string },
  api: string,
  severity: 'error' | 'warning' = 'error',
  kinds: readonly string[] = ['code'],
  cwe: readonly string[] = ['CWE-94'],
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds,
    severity,
    taintedArgs: [0],
    cwe,
    message: `${api} へ外部入力が到達しています（コードインジェクション）`,
    advice: CODE_ADVICE,
  });
}

/** NoSQL インジェクションシンクを作る。 */
function nosqlSink(id: string, pattern: { readonly member?: string; readonly call?: string }, api: string): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['nosql'],
    severity: 'warning',
    taintedArgs: [0],
    cwe: ['CWE-943'],
    message: `${api} へ外部入力が到達しています（NoSQL インジェクション）`,
    advice: NOSQL_ADVICE,
  });
}

/** オープンリダイレクトシンクを作る。 */
function redirectSink(
  id: string,
  pattern: { readonly member?: string; readonly call?: string },
  api: string,
  severity: 'error' | 'warning' = 'warning',
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['url'],
    severity,
    taintedArgs: [0],
    cwe: ['CWE-601'],
    message: `${api} のリダイレクト先が外部入力になっています（オープンリダイレクト）`,
    advice: REDIRECT_ADVICE,
  });
}

/**
 * オープンリダイレクト（プロパティ代入）のシンクを作る。
 *
 * `location.href = value` のような代入は「〜のリダイレクト先が…」ではなく
 * 「〜へ外部入力が代入されています」と書く。
 */
function redirectAssignmentSink(
  id: string,
  pattern: { readonly member?: string },
  target: string,
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['url'],
    severity: 'warning',
    taintedArgs: [0],
    cwe: ['CWE-601'],
    message: `${target} へ外部入力が代入されています（オープンリダイレクト）`,
    advice: REDIRECT_ADVICE,
  });
}

/** SSRF シンクを作る。 */
function ssrfSink(
  id: string,
  pattern: { readonly member?: string; readonly call?: string },
  api: string,
  taintedArgs: readonly number[] = [0],
): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['url'],
    severity: 'error',
    taintedArgs,
    cwe: ['CWE-918'],
    message: `${api} のリクエスト先が外部入力になっています（SSRF）`,
    advice: SSRF_ADVICE,
  });
}

/** ヘッダインジェクションシンクを作る。 */
function headerSink(id: string, pattern: { readonly member?: string; readonly call?: string }, api: string): SinkSpec {
  return withPattern(pattern, {
    id,
    kinds: ['header', 'url'],
    severity: 'warning',
    taintedArgs: [0],
    cwe: ['CWE-113'],
    message: `${api} へ外部入力が到達しています（ヘッダインジェクション / CRLF）`,
    advice: HEADER_ADVICE,
  });
}

// ---------------------------------------------------------------------------
// シンク
// ---------------------------------------------------------------------------

/**
 * 組み込みシンク。カテゴリごとの並びは「代表的なもの → 周辺 API」の順で固定しており、
 * 同じ式に複数のシンクが一致した場合は最も具体的なパターン（`member` 付き）が採用される。
 */
export const BUILTIN_SINKS: readonly SinkSpec[] = [
  // ------------------------------------------------------------------
  // CWE-89: SQL インジェクション
  // ------------------------------------------------------------------
  sqlSink('sql-query', { call: 'query' }, '`query()`'),
  sqlSink('sql-execute', { call: 'execute' }, '`execute()`'),
  sqlSink('sql-raw', { call: 'raw' }, '`raw()`'),
  sqlSink('sql-prepare', { call: 'prepare' }, '`prepare()`'),
  sqlSink('sql-query-raw', { call: 'queryRaw' }, 'Prisma `queryRaw()`'),
  sqlSink('sql-execute-raw', { call: 'executeRaw' }, 'Prisma `executeRaw()`'),
  sqlSink('sql-query-raw-unsafe', { call: '$queryRawUnsafe' }, 'Prisma `$queryRawUnsafe()`'),
  sqlSink('sql-execute-raw-unsafe', { call: '$executeRawUnsafe' }, 'Prisma `$executeRawUnsafe()`'),
  sqlSink('sql-knex-raw', { member: 'knex.raw', call: 'raw' }, '`knex.raw()`'),
  sqlSink('sql-sequelize-query', { member: 'sequelize.query', call: 'query' }, '`sequelize.query()`'),
  sqlSink('sql-db-exec', { member: 'db.exec', call: 'exec' }, '`db.exec()`'),

  // ------------------------------------------------------------------
  // CWE-79: クロスサイトスクリプティング
  // ------------------------------------------------------------------
  xssAssignmentSink('xss-inner-html', { member: '.innerHTML' }, '`element.innerHTML`'),
  xssAssignmentSink('xss-outer-html', { member: '.outerHTML' }, '`element.outerHTML`'),
  xssSink('xss-insert-adjacent-html', { call: 'insertAdjacentHTML' }, '`insertAdjacentHTML()`'),
  xssAssignmentSink('xss-dangerously-set-inner-html', { member: '.dangerouslySetInnerHTML' }, '`dangerouslySetInnerHTML`'),
  xssSink('xss-document-write', { member: 'document.write', call: 'write' }, '`document.write()`'),
  xssSink('xss-document-writeln', { member: 'document.writeln', call: 'writeln' }, '`document.writeln()`'),
  xssSink('xss-jquery-html', { call: 'html' }, '`html()`', 'warning'),
  xssSink('xss-res-send', { member: 'res.send', call: 'send' }, '`res.send()`', 'warning'),
  xssSink('xss-res-write', { member: 'res.write', call: 'write' }, '`res.write()`', 'warning'),
  xssSink('xss-res-end', { member: 'res.end', call: 'end' }, '`res.end()`', 'warning'),
  xssSink('xss-res-jsonp', { member: 'res.jsonp', call: 'jsonp' }, '`res.jsonp()`', 'warning'),
  xssSink('xss-reply-send', { member: 'reply.send', call: 'send' }, '`reply.send()`', 'warning'),
  xssAssignmentSink('xss-ctx-body', { member: 'ctx.body' }, '`ctx.body`', 'warning'),

  // ------------------------------------------------------------------
  // CWE-78: OS コマンドインジェクション
  // ------------------------------------------------------------------
  commandSink('command-exec', { call: 'exec' }, '`exec()`'),
  commandSink('command-exec-sync', { call: 'execSync' }, '`execSync()`'),
  commandSink('command-exec-file', { call: 'execFile' }, '`execFile()`'),
  commandSink('command-exec-file-sync', { call: 'execFileSync' }, '`execFileSync()`'),
  commandSink('command-spawn', { call: 'spawn' }, '`spawn()`'),
  commandSink('command-spawn-sync', { call: 'spawnSync' }, '`spawnSync()`'),
  withPattern({ call: 'fork' }, {
    id: 'command-fork',
    kinds: ['command'],
    severity: 'error',
    taintedArgs: [0],
    cwe: ['CWE-78'],
    message: '`fork()` に外部入力が到達しています（任意モジュールの実行）',
    advice: COMMAND_ADVICE,
  }),
  commandSink('command-child-process-exec', { member: 'child_process.exec', call: 'exec' }, '`child_process.exec()`'),
  commandSink('command-child-process-exec-sync', { member: 'child_process.execSync', call: 'execSync' }, '`child_process.execSync()`'),
  commandSink('command-child-process-fork', { member: 'child_process.fork', call: 'fork' }, '`child_process.fork()`'),
  commandSink('command-shelljs-exec', { member: 'shell.exec', call: 'exec' }, '`shelljs.exec()`'),

  // ------------------------------------------------------------------
  // CWE-22: パストラバーサル（fs 系）
  // ------------------------------------------------------------------
  pathSink('path-fs-read-file', { call: 'readFile' }, '`fs.readFile()`'),
  pathSink('path-fs-read-file-sync', { call: 'readFileSync' }, '`fs.readFileSync()`'),
  pathSink('path-fs-create-read-stream', { call: 'createReadStream' }, '`fs.createReadStream()`'),
  pathSink('path-fs-write-file', { call: 'writeFile' }, '`fs.writeFile()`'),
  pathSink('path-fs-write-file-sync', { call: 'writeFileSync' }, '`fs.writeFileSync()`'),
  pathSink('path-fs-create-write-stream', { call: 'createWriteStream' }, '`fs.createWriteStream()`'),
  pathSink('path-fs-append-file', { call: 'appendFile' }, '`fs.appendFile()`'),
  pathSink('path-fs-append-file-sync', { call: 'appendFileSync' }, '`fs.appendFileSync()`'),
  pathSink('path-fs-unlink', { call: 'unlink' }, '`fs.unlink()`'),
  pathSink('path-fs-unlink-sync', { call: 'unlinkSync' }, '`fs.unlinkSync()`'),
  pathSink('path-fs-rm', { call: 'rm' }, '`fs.rm()`'),
  pathSink('path-fs-rm-sync', { call: 'rmSync' }, '`fs.rmSync()`'),
  pathSink('path-fs-mkdir', { call: 'mkdir' }, '`fs.mkdir()`'),
  pathSink('path-fs-mkdir-sync', { call: 'mkdirSync' }, '`fs.mkdirSync()`'),
  pathSink('path-fs-readdir', { call: 'readdir' }, '`fs.readdir()`'),
  pathSink('path-fs-readdir-sync', { call: 'readdirSync' }, '`fs.readdirSync()`'),
  pathSink('path-fs-opendir', { call: 'opendir' }, '`fs.opendir()`'),
  pathSink('path-fs-stat', { call: 'stat' }, '`fs.stat()`'),
  pathSink('path-fs-stat-sync', { call: 'statSync' }, '`fs.statSync()`'),
  pathSink('path-fs-lstat', { call: 'lstat' }, '`fs.lstat()`'),
  pathSink('path-fs-open', { call: 'open' }, '`fs.open()`'),
  pathSink('path-fs-open-sync', { call: 'openSync' }, '`fs.openSync()`'),
  pathSink('path-fs-copy-file', { call: 'copyFile' }, '`fs.copyFile()`'),
  pathSink('path-fs-copy-file-sync', { call: 'copyFileSync' }, '`fs.copyFileSync()`'),
  pathSink('path-fs-rename', { call: 'rename' }, '`fs.rename()`'),
  pathSink('path-fs-rename-sync', { call: 'renameSync' }, '`fs.renameSync()`'),
  pathSink('path-fs-chmod', { call: 'chmod' }, '`fs.chmod()`'),
  pathSink('path-fs-chmod-sync', { call: 'chmodSync' }, '`fs.chmodSync()`'),
  pathSink('path-fs-symlink', { call: 'symlink' }, '`fs.symlink()`'),
  pathSink('path-fs-readlink', { call: 'readlink' }, '`fs.readlink()`'),
  pathSink('path-fs-realpath', { call: 'realpath' }, '`fs.realpath()`'),
  pathSink('path-fs-truncate', { call: 'truncate' }, '`fs.truncate()`'),

  // ------------------------------------------------------------------
  // CWE-22: パストラバーサル（Web / モジュール解決）
  // ------------------------------------------------------------------
  pathSink('path-res-send-file', { member: 'res.sendFile', call: 'sendFile' }, '`res.sendFile()`'),
  pathSink('path-reply-send-file', { member: 'reply.sendFile', call: 'sendFile' }, '`reply.sendFile()`'),
  pathSink('path-res-download', { member: 'res.download', call: 'download' }, '`res.download()`'),
  pathSink('path-send-file', { call: 'sendFile' }, '`sendFile()`'),
  pathSink('path-download', { call: 'download' }, '`download()`'),
  withPattern({ member: 'res.render', call: 'render' }, {
    id: 'path-res-render-view',
    kinds: ['path'],
    severity: 'warning',
    taintedArgs: [0],
    cwe: ['CWE-22'],
    message: '`res.render()` のテンプレート名へ外部入力が到達しています（パストラバーサル）',
    advice: PATH_ADVICE,
  }),
  withPattern({ call: 'require' }, {
    id: 'path-require',
    kinds: ['path'],
    severity: 'error',
    taintedArgs: [0],
    cwe: ['CWE-22'],
    message: '`require()` に外部入力が到達しています（任意モジュールの読み込み）',
    advice: 'モジュール名は許可リストで検証し、外部入力をそのまま `require` へ渡さないでください。',
  }),

  // ------------------------------------------------------------------
  // CWE-94 / CWE-95: コードインジェクション
  // ------------------------------------------------------------------
  codeSink('code-eval', { call: 'eval' }, '`eval()`'),
  codeSink('code-function-constructor', { call: 'Function' }, '`new Function()`'),
  withPattern({ call: 'setTimeout' }, {
    id: 'code-settimeout',
    kinds: ['code'],
    severity: 'warning',
    taintedArgs: [0],
    cwe: ['CWE-94'],
    message: '`setTimeout()` の第 1 引数に外部入力が到達しています（文字列はコードとして評価されます）',
    advice: CODE_ADVICE,
  }),
  withPattern({ call: 'setInterval' }, {
    id: 'code-setinterval',
    kinds: ['code'],
    severity: 'warning',
    taintedArgs: [0],
    cwe: ['CWE-94'],
    message: '`setInterval()` の第 1 引数に外部入力が到達しています（文字列はコードとして評価されます）',
    advice: CODE_ADVICE,
  }),
  codeSink('code-vm-run-in-new-context', { member: 'vm.runInNewContext', call: 'runInNewContext' }, '`vm.runInNewContext()`'),
  codeSink('code-vm-run-in-this-context', { member: 'vm.runInThisContext', call: 'runInThisContext' }, '`vm.runInThisContext()`'),
  codeSink('code-vm-run-in-context', { member: 'vm.runInContext', call: 'runInContext' }, '`vm.runInContext()`'),
  codeSink('code-vm-compile-function', { member: 'vm.compileFunction', call: 'compileFunction' }, '`vm.compileFunction()`'),
  codeSink('code-vm-script', { member: 'vm.Script' }, '`new vm.Script()`'),
  codeSink('code-node-serialize', { call: 'unserialize' }, '`unserialize()`', 'error', ['code'], ['CWE-502']),
  codeSink('code-lodash-template', { member: '_.template', call: 'template' }, '`_.template()`'),
  codeSink('code-handlebars-compile', { member: 'handlebars.compile', call: 'compile' }, '`handlebars.compile()`', 'error', ['code', 'html'], ['CWE-94', 'CWE-1336']),
  codeSink('code-ejs-render', { member: 'ejs.render', call: 'render' }, '`ejs.render()`', 'error', ['code', 'html'], ['CWE-94', 'CWE-1336']),
  codeSink('code-pug-render', { member: 'pug.render', call: 'render' }, '`pug.render()`', 'error', ['code', 'html'], ['CWE-94', 'CWE-1336']),
  codeSink('code-nunjucks-render-string', { member: 'nunjucks.renderString', call: 'renderString' }, '`nunjucks.renderString()`', 'error', ['code', 'html'], ['CWE-94', 'CWE-1336']),

  // ------------------------------------------------------------------
  // CWE-943: NoSQL インジェクション
  // ------------------------------------------------------------------
  nosqlSink('nosql-find', { call: 'find' }, '`find()`'),
  nosqlSink('nosql-find-one', { call: 'findOne' }, '`findOne()`'),
  nosqlSink('nosql-find-by-id', { call: 'findById' }, '`findById()`'),
  nosqlSink('nosql-find-one-and-update', { call: 'findOneAndUpdate' }, '`findOneAndUpdate()`'),
  nosqlSink('nosql-find-one-and-delete', { call: 'findOneAndDelete' }, '`findOneAndDelete()`'),
  nosqlSink('nosql-find-one-and-replace', { call: 'findOneAndReplace' }, '`findOneAndReplace()`'),
  nosqlSink('nosql-update-one', { call: 'updateOne' }, '`updateOne()`'),
  nosqlSink('nosql-update-many', { call: 'updateMany' }, '`updateMany()`'),
  nosqlSink('nosql-delete-one', { call: 'deleteOne' }, '`deleteOne()`'),
  nosqlSink('nosql-delete-many', { call: 'deleteMany' }, '`deleteMany()`'),
  nosqlSink('nosql-replace-one', { call: 'replaceOne' }, '`replaceOne()`'),
  nosqlSink('nosql-count-documents', { call: 'countDocuments' }, '`countDocuments()`'),
  nosqlSink('nosql-distinct', { call: 'distinct' }, '`distinct()`'),
  nosqlSink('nosql-aggregate', { call: 'aggregate' }, '`aggregate()`'),
  nosqlSink('nosql-bulk-write', { call: 'bulkWrite' }, '`bulkWrite()`'),
  nosqlSink('nosql-map-reduce', { call: 'mapReduce' }, '`mapReduce()`'),
  withPattern({ member: '.$where' }, {
    id: 'nosql-where-operator',
    kinds: ['code', 'nosql'],
    severity: 'error',
    cwe: ['CWE-943'],
    message: 'MongoDB の `$where` に外部入力が到達しています（サーバ側での JS 実行）',
    advice: NOSQL_ADVICE,
  }),

  // ------------------------------------------------------------------
  // CWE-601: オープンリダイレクト
  // ------------------------------------------------------------------
  redirectSink('redirect-res', { member: 'res.redirect', call: 'redirect' }, '`res.redirect()`'),
  redirectSink('redirect-reply', { member: 'reply.redirect', call: 'redirect' }, '`reply.redirect()`'),
  redirectSink('redirect-ctx', { member: 'ctx.redirect', call: 'redirect' }, '`ctx.redirect()`'),
  redirectSink('redirect-bare', { call: 'redirect' }, '`redirect()`'),
  redirectSink('redirect-res-location', { member: 'res.location', call: 'location' }, '`res.location()`'),
  redirectSink('redirect-location-assign', { member: 'location.assign', call: 'assign' }, '`location.assign()`'),
  redirectSink('redirect-location-replace', { member: 'location.replace', call: 'replace' }, '`location.replace()`'),
  redirectAssignmentSink('redirect-location-href', { member: 'location.href' }, '`location.href`'),
  redirectAssignmentSink('redirect-window-location', { member: 'window.location' }, '`window.location`'),
  redirectSink('redirect-navigate', { call: 'navigate' }, '`navigate()`'),
  redirectSink('redirect-router-push', { member: 'router.push', call: 'push' }, '`router.push()`'),

  // ------------------------------------------------------------------
  // CWE-918: SSRF
  // ------------------------------------------------------------------
  ssrfSink('ssrf-fetch', { call: 'fetch' }, '`fetch()`'),
  ssrfSink('ssrf-axios-get', { member: 'axios.get', call: 'get' }, '`axios.get()`'),
  ssrfSink('ssrf-axios-post', { member: 'axios.post', call: 'post' }, '`axios.post()`'),
  ssrfSink('ssrf-axios-put', { member: 'axios.put', call: 'put' }, '`axios.put()`'),
  ssrfSink('ssrf-axios-patch', { member: 'axios.patch', call: 'patch' }, '`axios.patch()`'),
  ssrfSink('ssrf-axios-delete', { member: 'axios.delete', call: 'delete' }, '`axios.delete()`'),
  ssrfSink('ssrf-axios-head', { member: 'axios.head', call: 'head' }, '`axios.head()`'),
  ssrfSink('ssrf-axios-options', { member: 'axios.options', call: 'options' }, '`axios.options()`'),
  ssrfSink('ssrf-axios-request', { member: 'axios.request', call: 'request' }, '`axios.request()`'),
  ssrfSink('ssrf-axios-call', { call: 'axios' }, '`axios()`'),
  ssrfSink('ssrf-http-request', { member: 'http.request', call: 'request' }, '`http.request()`'),
  ssrfSink('ssrf-http-get', { member: 'http.get', call: 'get' }, '`http.get()`'),
  ssrfSink('ssrf-https-request', { member: 'https.request', call: 'request' }, '`https.request()`'),
  ssrfSink('ssrf-https-get', { member: 'https.get', call: 'get' }, '`https.get()`'),
  ssrfSink('ssrf-undici-request', { member: 'undici.request', call: 'request' }, '`undici.request()`'),
  ssrfSink('ssrf-got', { call: 'got' }, '`got()`'),
  ssrfSink('ssrf-request', { call: 'request' }, '`request()`'),
  ssrfSink('ssrf-superagent', { member: 'superagent.get', call: 'get' }, '`superagent.get()`'),
  ssrfSink('ssrf-websocket', { call: 'WebSocket' }, '`new WebSocket()`'),
  ssrfSink('ssrf-net-connect', { member: 'net.connect', call: 'connect' }, '`net.connect()`', [1]),
  ssrfSink('ssrf-tls-connect', { member: 'tls.connect', call: 'connect' }, '`tls.connect()`', [1]),

  // ------------------------------------------------------------------
  // CWE-113: ヘッダインジェクション
  // ------------------------------------------------------------------
  headerSink('header-res-set-header', { member: 'res.setHeader', call: 'setHeader' }, '`res.setHeader()`'),
  headerSink('header-res-set', { member: 'res.set', call: 'set' }, '`res.set()`'),
  headerSink('header-res-header', { member: 'res.header', call: 'header' }, '`res.header()`'),
  headerSink('header-res-cookie', { member: 'res.cookie', call: 'cookie' }, '`res.cookie()`'),
  headerSink('header-reply-header', { member: 'reply.header', call: 'header' }, '`reply.header()`'),
  headerSink('header-ctx-set', { member: 'ctx.set', call: 'set' }, '`ctx.set()`'),
  headerSink('header-ctx-cookies-set', { member: 'ctx.cookies.set', call: 'set' }, '`ctx.cookies.set()`'),

  // ------------------------------------------------------------------
  // 情報提供（note）: DOM の URL 系プロパティ
  // ------------------------------------------------------------------
  withPattern({ member: '.href' }, {
    id: 'note-dom-href',
    kinds: ['url'],
    severity: 'note',
    cwe: ['CWE-79'],
    message: 'DOM の `href` へ外部入力が代入されています（`javascript:` スキームの可能性）',
    advice: 'スキームを検証し、`http:` / `https:` 以外を拒否してください。',
  }),
  withPattern({ member: '.src' }, {
    id: 'note-dom-src',
    kinds: ['url'],
    severity: 'note',
    taintedArgs: [0],
    cwe: ['CWE-79'],
    message: 'DOM の `src` へ外部入力が代入されています（スクリプト読み込みの可能性）',
    advice: '読み込み先を許可リストで検証してください。',
  }),
] satisfies readonly SinkSpec[];

// ---------------------------------------------------------------------------
// 伝播規則
// ---------------------------------------------------------------------------

/** 文字列・配列の素通しメソッド（引数の汚染が戻り値へ伝わる）。 */
const PASSTHROUGH_CALLS: readonly string[] = [
  'concat',
  'join',
  'slice',
  'substring',
  'substr',
  'trim',
  'trimStart',
  'trimEnd',
  'toLowerCase',
  'toUpperCase',
  'replace',
  'replaceAll',
  'split',
  'padStart',
  'padEnd',
  'repeat',
  'normalize',
  'charAt',
  'toString',
  'map',
  'filter',
  'flat',
  'flatMap',
  'reduce',
  'sort',
  'reverse',
];

/**
 * 組み込み伝播規則。
 *
 * IR 構築側が扱う代入・引数・戻り値・テンプレート・連結に加えて、
 * 「引数がそのまま戻り値へ流れる」ライブラリ関数を宣言する。
 * ここに載っていない関数は伝播しないため、誤検出を増やさない範囲で列挙する。
 */
export const BUILTIN_PROPAGATORS: readonly PatternSpec[] = [
  // 標準ライブラリ
  { member: 'JSON.parse' },
  { member: 'JSON.stringify' },
  { member: 'Object.assign' },
  { member: 'Object.fromEntries' },
  { member: 'Array.from' },
  { member: 'Array.of' },
  { call: 'String' },
  { call: 'Boolean' },
  { member: 'Buffer.from' },
  { member: 'Buffer.concat' },
  { call: 'decodeURI' },
  { call: 'decodeURIComponent' },
  { call: 'encodeURI' },
  { member: 'URLSearchParams' },
  { member: 'querystring.parse' },
  { member: 'querystring.stringify' },
  { member: 'qs.parse' },
  { member: 'qs.stringify' },
  { member: 'url.parse' },
  { member: 'path.join' },
  { member: 'path.resolve' },
  { member: 'path.normalize' },
  { member: 'path.dirname' },
  { member: 'util.format' },
  { member: 'util.inspect' },

  // 文字列・配列の素通しメソッド
  ...PASSTHROUGH_CALLS.map((name) => ({ call: name }) satisfies PatternSpec),

  // ユーティリティライブラリ（lodash）
  { member: '_.get' },
  { member: '_.merge' },
  { member: '_.assign' },
  { member: '_.clone' },
  { member: '_.cloneDeep' },
  { member: '_.pick' },
  { member: '_.omit' },
  { member: '_.defaults' },
  { member: '_.values' },

  // フレームワークの素通し（テンプレートへ値を渡すだけの API）
  { member: 'res.locals' },
  { member: 'app.locals' },
  { member: 'ctx.state' },
  { member: 'request.headers' },
] satisfies readonly PatternSpec[];
