/**
 * 組み込みルールセットの網羅性と整合性を固定する。
 *
 * 「5 件のスタブ」ではなく実用的なルールセットであることを、件数・CWE カバレッジ・
 * フレームワーク別の代表 API の 3 つの軸で検証する。
 */
import { describe, expect, it } from 'vitest';
import {
  BUILTIN_PROPAGATORS,
  BUILTIN_SANITIZERS,
  BUILTIN_SINKS,
  BUILTIN_SOURCES,
  DEFAULT_ANALYSIS,
  DEFAULT_IGNORE_PATHS,
  DEFAULT_OUTPUT,
} from '../../src/rules/builtin.js';
import { matchesPattern, parseExpression } from '../../src/rules/match.js';

/** ドキュメントで固定されているタグ語彙。 */
const TAG_VOCABULARY = ['code', 'command', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url'];

describe('組み込みルール: 規模', () => {
  it('ソースは 8 件以上ある（実際は 30 件超）', () => {
    expect(BUILTIN_SOURCES.length).toBeGreaterThanOrEqual(8);
    expect(BUILTIN_SOURCES.length).toBeGreaterThanOrEqual(30);
  });

  it('サニタイザは 8 件以上ある（実際は 30 件超）', () => {
    expect(BUILTIN_SANITIZERS.length).toBeGreaterThanOrEqual(8);
    expect(BUILTIN_SANITIZERS.length).toBeGreaterThanOrEqual(30);
  });

  it('シンクは 25 件以上ある（実際は 100 件超）', () => {
    expect(BUILTIN_SINKS.length).toBeGreaterThanOrEqual(25);
    expect(BUILTIN_SINKS.length).toBeGreaterThanOrEqual(100);
  });

  it('伝播規則は 20 件以上ある', () => {
    expect(BUILTIN_PROPAGATORS.length).toBeGreaterThanOrEqual(20);
  });

  it('id はカテゴリごとに一意である', () => {
    const sourceIds = BUILTIN_SOURCES.map((spec) => spec.id);
    const sanitizerIds = BUILTIN_SANITIZERS.map((spec) => spec.id);
    const sinkIds = BUILTIN_SINKS.map((spec) => spec.id);
    expect(new Set(sourceIds).size).toBe(sourceIds.length);
    expect(new Set(sanitizerIds).size).toBe(sanitizerIds.length);
    expect(new Set(sinkIds).size).toBe(sinkIds.length);
  });
});

describe('組み込みルール: 構造の整合性', () => {
  it('すべての規則が member / identifier / call のいずれかを持つ', () => {
    for (const spec of [...BUILTIN_SOURCES, ...BUILTIN_SANITIZERS, ...BUILTIN_SINKS, ...BUILTIN_PROPAGATORS]) {
      const hasPattern = spec.member !== undefined || spec.identifier !== undefined || spec.call !== undefined;
      const name = 'id' in spec ? spec.id : (spec.member ?? spec.call ?? spec.identifier ?? '<pattern>');
      expect(hasPattern, `${name} に照合条件がありません`).toBe(true);
    }
  });

  it('タグはドキュメント上の語彙だけを使う', () => {
    const kinds = new Set<string>();
    for (const spec of BUILTIN_SOURCES) for (const kind of spec.kinds) kinds.add(kind);
    for (const spec of BUILTIN_SANITIZERS) for (const kind of spec.kinds) kinds.add(kind);
    for (const spec of BUILTIN_SINKS) for (const kind of spec.kinds) kinds.add(kind);
    for (const kind of kinds) {
      expect(TAG_VOCABULARY, `未知のタグ: ${kind}`).toContain(kind);
    }
    expect(kinds.size).toBe(TAG_VOCABULARY.length);
  });

  it('ソースの kinds は空でない', () => {
    for (const spec of BUILTIN_SOURCES) {
      expect(spec.kinds.length, `${spec.id} の kinds が空です`).toBeGreaterThan(0);
    }
  });

  it('シンクの kinds は空でなく、severity と message が妥当', () => {
    for (const spec of BUILTIN_SINKS) {
      expect(spec.kinds.length, `${spec.id} の kinds が空です`).toBeGreaterThan(0);
      expect(['error', 'warning', 'note']).toContain(spec.severity);
      expect(spec.message.length, `${spec.id} の message が空です`).toBeGreaterThan(0);
      for (const index of spec.taintedArgs ?? []) {
        expect(Number.isInteger(index) && index >= 0, `${spec.id} の taintedArgs が不正です`).toBe(true);
      }
    }
  });

  it('サニタイザの validation は既知の値だけを使う', () => {
    for (const spec of BUILTIN_SANITIZERS) {
      expect(['static-sql', 'constant-argument', 'none']).toContain(spec.validation ?? 'none');
    }
  });

  it('すべての規則が日本語の説明または注意書きを持つ', () => {
    for (const spec of BUILTIN_SOURCES) expect(spec.description, `${spec.id}`).toBeTruthy();
    for (const spec of BUILTIN_SANITIZERS) expect(spec.description, `${spec.id}`).toBeTruthy();
    for (const spec of BUILTIN_SINKS) expect(spec.advice, `${spec.id}`).toBeTruthy();
  });
});

describe('組み込みルール: CWE カバレッジ', () => {
  const cwesOf = (prefix: string): Set<string> => {
    const ids = new Set<string>();
    for (const spec of BUILTIN_SINKS) {
      for (const cwe of spec.cwe ?? []) {
        if (cwe.startsWith(`CWE-${prefix}`)) ids.add(cwe);
      }
    }
    return ids;
  };

  it('要求された 8 種類の CWE をカバーする', () => {
    const all = new Set<string>();
    for (const spec of BUILTIN_SINKS) for (const cwe of spec.cwe ?? []) all.add(cwe);
    for (const required of ['CWE-89', 'CWE-79', 'CWE-78', 'CWE-22', 'CWE-94', 'CWE-943', 'CWE-601', 'CWE-918']) {
      expect(all, `${required} がありません`).toContain(required);
    }
  });

  it('CWE-89 (SQLi) のシンクが 5 件以上ある', () => {
    expect(cwesOf('89').size).toBeGreaterThan(0);
    expect(BUILTIN_SINKS.filter((spec) => (spec.cwe ?? []).includes('CWE-89')).length).toBeGreaterThanOrEqual(5);
  });

  it('CWE-79 (XSS) のシンクが 8 件以上ある', () => {
    expect(BUILTIN_SINKS.filter((spec) => (spec.cwe ?? []).includes('CWE-79')).length).toBeGreaterThanOrEqual(8);
  });

  it('CWE-78 (OS コマンド) のシンクが 5 件以上ある', () => {
    expect(BUILTIN_SINKS.filter((spec) => (spec.cwe ?? []).includes('CWE-78')).length).toBeGreaterThanOrEqual(5);
  });

  it('CWE-22 (パストラバーサル) のシンクが 15 件以上ある', () => {
    expect(BUILTIN_SINKS.filter((spec) => (spec.cwe ?? []).includes('CWE-22')).length).toBeGreaterThanOrEqual(15);
  });

  it('CWE-943 (NoSQL) のシンクが 8 件以上ある', () => {
    expect(BUILTIN_SINKS.filter((spec) => (spec.cwe ?? []).includes('CWE-943')).length).toBeGreaterThanOrEqual(8);
  });

  it('CWE-918 (SSRF) のシンクが 8 件以上ある', () => {
    expect(BUILTIN_SINKS.filter((spec) => (spec.cwe ?? []).includes('CWE-918')).length).toBeGreaterThanOrEqual(8);
  });

  it('重要度は error / warning / note のすべてを使う', () => {
    const severities = new Set(BUILTIN_SINKS.map((spec) => spec.severity));
    expect([...severities].sort()).toEqual(['error', 'note', 'warning']);
  });
});

describe('組み込みソース: 代表 API のカバレッジ', () => {
  const covers = (pattern: { member?: string; identifier?: string; call?: string }): boolean =>
    BUILTIN_SOURCES.some((spec) => spec.member === pattern.member && spec.identifier === pattern.identifier && spec.call === pattern.call);

  it('Express / Connect のリクエスト部位を網羅する', () => {
    for (const member of ['req.query', 'req.body', 'req.params', 'req.headers', 'req.cookies', 'req.url', 'req.originalUrl', 'req.path']) {
      expect(covers({ member }), `${member} がありません`).toBe(true);
    }
  });

  it('Koa の ctx を網羅する', () => {
    for (const member of ['ctx.query', 'ctx.params', 'ctx.headers', 'ctx.request.body', 'ctx.cookies.get']) {
      expect(covers({ member }), `${member} がありません`).toBe(true);
    }
  });

  it('Fastify / NestJS の request を網羅する', () => {
    for (const member of ['request.query', 'request.body', 'request.params', 'request.headers']) {
      expect(covers({ member }), `${member} がありません`).toBe(true);
    }
  });

  it('ブラウザ (DOM) のソースを網羅する', () => {
    for (const member of ['location.search', 'location.hash', 'location.href', 'window.name', 'document.URL', 'document.referrer', 'document.cookie']) {
      expect(covers({ member }), `${member} がありません`).toBe(true);
    }
  });

  it('Node 実行環境のソースを網羅する', () => {
    expect(covers({ member: 'process.argv' })).toBe(true);
    expect(covers({ member: 'process.env' })).toBe(true);
  });

  it('引数 `req` / `request` そのものをソースとして宣言する', () => {
    expect(covers({ identifier: 'req' })).toBe(true);
    expect(covers({ identifier: 'request' })).toBe(true);
  });

  it('Lambda / API Gateway のイベントをソースとして宣言する', () => {
    expect(covers({ member: 'event.queryStringParameters' })).toBe(true);
    expect(covers({ member: 'event.body' })).toBe(true);
  });

  it('`req.query` は `req.query.id` に接頭辞一致する', () => {
    const source = BUILTIN_SOURCES.find((spec) => spec.member === 'req.query');
    expect(source).toBeDefined();
    expect(matchesPattern(source ?? {}, parseExpression('req.query.id'))).toBe(true);
  });
});

describe('組み込みサニタイザ: 代表 API のカバレッジ', () => {
  const has = (id: string): boolean => BUILTIN_SANITIZERS.some((spec) => spec.id === id);

  it('SQL のプレースホルダ用法を static-sql で宣言する', () => {
    for (const id of ['sql-db-query', 'sql-connection-query', 'sql-pool-query', 'sql-sequelize-query', 'sql-knex-raw']) {
      expect(has(id), `${id} がありません`).toBe(true);
    }
    const dbQuery = BUILTIN_SANITIZERS.find((spec) => spec.id === 'sql-db-query');
    expect(dbQuery?.validation).toBe('static-sql');
    expect(dbQuery?.member).toBe('db.query');
  });

  it('HTML サニタイザを網羅する', () => {
    for (const id of ['html-escape-html', 'html-escape', 'html-dompurify-sanitize', 'html-he-encode', 'html-encode-uri-component']) {
      expect(has(id), `${id} がありません`).toBe(true);
    }
  });

  it('コマンド・パス・NoSQL・URL のサニタイザを持つ', () => {
    for (const id of ['command-shell-quote', 'command-exec-file-constant', 'path-basename', 'nosql-mongo-sanitize', 'url-sanitize-url']) {
      expect(has(id), `${id} がありません`).toBe(true);
    }
  });

  it('パス正規化（path.join / path.resolve）はサニタイザにしない', () => {
    // 基準ディレクトリが定数でも `..` は正規化されるだけで拒否されないため、
    // path.join / path.resolve をサニタイザにすると CWE-22 の検出漏れになる。
    expect(BUILTIN_SANITIZERS.some((spec) => spec.member === 'path.join')).toBe(false);
    expect(BUILTIN_SANITIZERS.some((spec) => spec.member === 'path.resolve')).toBe(false);
    const basename = BUILTIN_SANITIZERS.find((spec) => spec.id === 'path-basename');
    expect(basename?.kinds).toEqual(['path']);
    expect(basename?.validation).toBe('none');
  });

  it('path.join は伝播規則として残る（タグはシンクまで運ばれる）', () => {
    expect(BUILTIN_PROPAGATORS.some((spec) => spec.member === 'path.join')).toBe(true);
  });

  it('数値強制による無害化を宣言する', () => {
    for (const id of ['coerce-parse-int', 'coerce-number', 'coerce-parse-float']) {
      expect(has(id), `${id} がありません`).toBe(true);
    }
    const parse = BUILTIN_SANITIZERS.find((spec) => spec.id === 'coerce-parse-int');
    expect(parse?.kinds).toContain('sql');
    expect(parse?.kinds).toContain('path');
  });
});

describe('組み込みシンク: 代表 API のカバレッジ', () => {
  const ids = new Set(BUILTIN_SINKS.map((spec) => spec.id));

  it('CWE-89: クエリ実行 API', () => {
    for (const id of ['sql-query', 'sql-execute', 'sql-raw', 'sql-knex-raw', 'sql-sequelize-query', 'sql-query-raw-unsafe']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-79: DOM / レスポンスの XSS シンク', () => {
    for (const id of ['xss-inner-html', 'xss-outer-html', 'xss-document-write', 'xss-insert-adjacent-html', 'xss-dangerously-set-inner-html', 'xss-res-send']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-78: child_process のシンク', () => {
    for (const id of ['command-exec', 'command-exec-sync', 'command-spawn', 'command-exec-file', 'command-fork', 'command-child-process-exec']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-22: fs とレスポンスのシンク', () => {
    for (const id of ['path-fs-read-file', 'path-fs-write-file', 'path-fs-create-read-stream', 'path-res-send-file', 'path-res-download', 'path-require']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-94: 動的評価のシンク', () => {
    for (const id of ['code-eval', 'code-function-constructor', 'code-vm-run-in-new-context', 'code-settimeout']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-943: NoSQL のシンク', () => {
    for (const id of ['nosql-find', 'nosql-find-one', 'nosql-update-one', 'nosql-delete-many', 'nosql-aggregate', 'nosql-where-operator']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-601: リダイレクトのシンク', () => {
    for (const id of ['redirect-res', 'redirect-reply', 'redirect-ctx', 'redirect-location-assign', 'redirect-location-href', 'redirect-window-location']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('CWE-918: SSRF のシンク', () => {
    for (const id of ['ssrf-fetch', 'ssrf-axios-get', 'ssrf-http-request', 'ssrf-https-get', 'ssrf-net-connect', 'ssrf-websocket']) {
      expect(ids.has(id), `${id} がありません`).toBe(true);
    }
  });

  it('先頭 `.` の接尾辞パターン（レシーバ不定のプロパティ）を持つ', () => {
    const suffixes = BUILTIN_SINKS.filter((spec) => spec.member?.startsWith('.') === true);
    expect(suffixes.length).toBeGreaterThanOrEqual(2);
    expect(suffixes.map((spec) => spec.member)).toContain('.innerHTML');
    expect(suffixes.map((spec) => spec.member)).toContain('.$where');
  });

  it('`db.query` はシンクとサニタイザの両方に現れる（プレースホルダ検証の中核）', () => {
    expect(BUILTIN_SANITIZERS.some((spec) => spec.member === 'db.query' && spec.validation === 'static-sql')).toBe(true);
    const querySink = BUILTIN_SINKS.find((spec) => spec.id === 'sql-query');
    expect(querySink?.call).toBe('query');
    expect(querySink?.taintedArgs).toEqual([0]);
  });
});

describe('既定の解析・出力設定', () => {
  it('DEFAULT_ANALYSIS は正の上限を持つ', () => {
    expect(DEFAULT_ANALYSIS.maxCallDepth).toBeGreaterThan(0);
    expect(DEFAULT_ANALYSIS.maxIterations).toBeGreaterThan(0);
    expect(DEFAULT_ANALYSIS.dedupe).toBe(true);
  });

  it('DEFAULT_OUTPUT は pretty 出力で error を CI ゲートにする', () => {
    expect(DEFAULT_OUTPUT.format).toBe('pretty');
    expect(DEFAULT_OUTPUT.failOn).toBe('error');
  });

  it('DEFAULT_IGNORE_PATHS は依存物と生成物を除外する', () => {
    expect(DEFAULT_IGNORE_PATHS).toContain('**/node_modules/**');
    expect(DEFAULT_IGNORE_PATHS).toContain('**/dist/**');
    expect(DEFAULT_IGNORE_PATHS).toContain('**/*.d.ts');
  });
});

describe('組み込みシンク: メッセージの品質', () => {
  it('プロパティ代入系の XSS は「に…を代入しています」と書く', () => {
    for (const id of ['xss-inner-html', 'xss-outer-html', 'xss-dangerously-set-inner-html', 'xss-ctx-body']) {
      const spec = BUILTIN_SINKS.find((item) => item.id === id);
      expect(spec?.message, `${id} のメッセージ`).toMatch(/に未エスケープの外部入力を代入しています（クロスサイトスクリプティング）$/);
    }
    expect(BUILTIN_SINKS.find((item) => item.id === 'xss-inner-html')?.message).toBe(
      '`element.innerHTML` に未エスケープの外部入力を代入しています（クロスサイトスクリプティング）',
    );
  });

  it('プロパティ代入系のリダイレクトは「へ…が代入されています」と書く', () => {
    for (const id of ['redirect-location-href', 'redirect-window-location']) {
      const spec = BUILTIN_SINKS.find((item) => item.id === id);
      expect(spec?.message, `${id} のメッセージ`).toMatch(/へ外部入力が代入されています（オープンリダイレクト）$/);
    }
  });

  it('どのメッセージにも二重助詞（「への代入 へ」など）が現れない', () => {
    for (const spec of BUILTIN_SINKS) {
      expect(spec.message, `${spec.id}: ${spec.message}`).not.toMatch(/(への代入|の代入)\s*へ/);
      expect(spec.message, `${spec.id}: ${spec.message}`).not.toMatch(/）\s+へ/);
    }
  });
});

describe('組み込みルール: 決定性', () => {
  it('同じ読み取りに対して同じ順序を返す（配列は変更されない）', () => {
    const first = BUILTIN_SINKS.map((spec) => spec.id);
    const second = BUILTIN_SINKS.map((spec) => spec.id);
    expect(first).toEqual(second);
    expect(BUILTIN_SOURCES.map((spec) => spec.id)).toEqual(BUILTIN_SOURCES.map((spec) => spec.id));
  });
});
