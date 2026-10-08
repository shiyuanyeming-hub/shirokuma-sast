/**
 * `annotate()` の挙動を固定する。
 *
 * IR グラフはテスト内で直接組み立てる（`src/ir/builder.ts` に依存しない）。
 * ソース／サニタイザ／シンクの確定と、その順序の決定性を確認する。
 */
import { describe, expect, it } from 'vitest';
import type {
  FlowKind,
  FlowNode,
  FunctionIR,
  IRGraph,
  PatternSpec,
  ResolvedRuleSet,
  SanitizerSpec,
  SinkSpec,
  SourceSpec,
} from '../../src/types.js';
import { annotate, annotateGraph } from '../../src/rules/annotate.js';
import {
  BUILTIN_PROPAGATORS,
  BUILTIN_SANITIZERS,
  BUILTIN_SINKS,
  BUILTIN_SOURCES,
  DEFAULT_IGNORE_PATHS,
} from '../../src/rules/builtin.js';
import { resolveRuleSet } from '../../src/config/loader.js';

/** 検出位置を持たないテスト用ノードを作る。 */
function node(id: string, label: string, options: { kind?: FlowKind; text?: string; functionId?: string; line?: number } = {}): FlowNode {
  const line = options.line ?? 1;
  return {
    id,
    kind: options.kind ?? 'unknown',
    functionId: options.functionId ?? 'a.ts::handler',
    range: { start: { line, column: 1 }, end: { line, column: 1 + label.length } },
    label,
    ...(options.text !== undefined ? { text: options.text } : {}),
  };
}

/** テスト用の関数を作る。 */
function fn(id: string, name: string, options: { className?: string } = {}): FunctionIR {
  return {
    id,
    name,
    ...(options.className !== undefined ? { className: options.className } : {}),
    file: id.split('::')[0] ?? 'a.ts',
    range: { start: { line: 1, column: 1 }, end: { line: 10, column: 1 } },
    params: [],
    bodyRange: { start: { line: 1, column: 1 }, end: { line: 10, column: 1 } },
    callees: [],
    analysable: true,
  };
}

/** テスト用のグラフを作る。 */
function graphOf(nodes: readonly FlowNode[], functions: readonly FunctionIR[] = []): IRGraph {
  return {
    functions,
    nodes,
    edges: [],
    callSites: [],
    functionsByFile: new Map(),
    nodeById: new Map(nodes.map((item) => [item.id, item])),
    functionById: new Map(functions.map((item) => [item.id, item])),
  };
}

/** 索引だけを張ったルールセットを作る（検証器を通さず、照合の挙動だけを見る）。 */
function rulesOf(partial: {
  readonly sources?: readonly SourceSpec[];
  readonly sanitizers?: readonly SanitizerSpec[];
  readonly sinks?: readonly SinkSpec[];
  readonly propagators?: readonly PatternSpec[];
  readonly ignorePaths?: readonly string[];
}): ResolvedRuleSet {
  const sources = partial.sources ?? [];
  const sanitizers = partial.sanitizers ?? [];
  const sinks = partial.sinks ?? [];
  const propagators = partial.propagators ?? [];
  return {
    sources,
    sanitizers,
    sinks,
    propagators,
    ignorePaths: partial.ignorePaths ?? [],
    sinkById: new Map(sinks.map((spec) => [spec.id, spec])),
    sourceById: new Map(sources.map((spec) => [spec.id, spec])),
    sanitizerById: new Map(sanitizers.map((spec) => [spec.id, spec])),
  };
}

/** 組み込みルールをそのまま使うルールセット。 */
const builtinRules = rulesOf({
  sources: BUILTIN_SOURCES,
  sanitizers: BUILTIN_SANITIZERS,
  sinks: BUILTIN_SINKS,
  propagators: BUILTIN_PROPAGATORS,
  ignorePaths: DEFAULT_IGNORE_PATHS,
});

describe('annotate: ソースの確定', () => {
  it('接頭辞一致で `req.query` が `req.query.id` にも一致する', () => {
    const result = annotate(graphOf([node('n1', 'req.query.id')]), builtinRules);
    expect(result.sources).toHaveLength(1);
    expect(result.sources[0]?.sourceId).toBe('express-query');
    expect(result.sources[0]?.nodeId).toBe('n1');
    expect(result.sources[0]?.kinds).toContain('sql');
  });

  it('引数 `req` そのものは identifier 指定のソースに一致する', () => {
    const result = annotate(graphOf([node('n1', 'req', { kind: 'param' })]), builtinRules);
    expect(result.sources.map((item) => item.sourceId)).toEqual(['express-request-identifier']);
  });

  it('同じノードに複数のソースが一致した場合は最も具体的な 1 件だけを採用する', () => {
    const rules = rulesOf({
      sources: [
        { id: 'wide', member: 'req.query', kinds: ['html'] },
        { id: 'narrow', member: 'req.query.id', kinds: ['sql'] },
      ],
    });
    const result = annotate(graphOf([node('n1', 'req.query.id')]), rules);
    expect(result.sources.map((item) => item.sourceId)).toEqual(['narrow']);
    expect(result.sources[0]?.kinds).toEqual(['sql']);
  });

  it('withinFunctions に一致しない関数のソースは確定しない', () => {
    const rules = rulesOf({
      sources: [{ id: 'scoped', member: 'req.query', kinds: ['sql'], withinFunctions: ['handler'] }],
    });
    const functions = [fn('a.ts::handler', 'handler'), fn('a.ts::other', 'other')];
    const matched = annotate(graphOf([node('n1', 'req.query', { functionId: 'a.ts::handler' })], functions), rules);
    const unmatched = annotate(graphOf([node('n2', 'req.query', { functionId: 'a.ts::other' })], functions), rules);
    expect(matched.sources).toHaveLength(1);
    expect(unmatched.sources).toHaveLength(0);
  });

  it('withinFunctions は `Class.method` 形式でも一致する', () => {
    const rules = rulesOf({
      sources: [{ id: 'scoped', member: 'req.body', kinds: ['sql'], withinFunctions: ['Controller.create'] }],
    });
    const functions = [fn('a.ts::Controller.create', 'create', { className: 'Controller' })];
    const result = annotate(graphOf([node('n1', 'req.body', { functionId: 'a.ts::Controller.create' })], functions), rules);
    expect(result.sources).toHaveLength(1);
  });

  it('動的プロパティは allowDynamic を指定した規則にだけ一致する', () => {
    const strict = rulesOf({ sources: [{ id: 'strict', member: 'req.query', kinds: ['sql'] }] });
    // allowDynamic は照合器の汎用機能であり、SourceSpec の型には現れない（実行時のみ有効）。
    const lenient = rulesOf({ sources: [{ id: 'lenient', member: 'req.query', kinds: ['sql'], allowDynamic: true } as SourceSpec] });
    expect(annotate(graphOf([node('n1', 'req[userKey]')]), strict).sources).toHaveLength(0);
    expect(annotate(graphOf([node('n1', 'req[userKey]')]), lenient).sources).toHaveLength(1);
  });
});

describe('annotate: サニタイザの検証', () => {
  it('プレースホルダ用法の `db.query` は有効', () => {
    const graph = graphOf([node('n1', "db.query('SELECT * FROM users WHERE id = ?', [id])", { kind: 'call' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sanitizers).toHaveLength(1);
    expect(result.sanitizers[0]?.sanitizerId).toBe('sql-db-query');
    expect(result.sanitizers[0]?.valid).toBe(true);
    expect(result.sanitizers[0]?.invalidReason).toBeUndefined();
  });

  it('変数を渡した `db.query(sql)` は無効（汚染が残る）', () => {
    const graph = graphOf([node('n1', 'db.query(sql)', { kind: 'call' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sanitizers[0]?.valid).toBe(false);
    expect(result.sanitizers[0]?.invalidReason).toContain('SQL 文が文字列リテラルではない');
  });

  it('補間ありテンプレートの `db.query` は無効', () => {
    const graph = graphOf([node('n1', 'db.query(`SELECT * FROM users WHERE id = ${id}`)', { kind: 'call' })]);
    expect(annotate(graph, builtinRules).sanitizers[0]?.valid).toBe(false);
  });

  it('補間なしテンプレートの `db.query` は有効', () => {
    const graph = graphOf([node('n1', 'db.query(`SELECT 1`)', { kind: 'call' })]);
    expect(annotate(graph, builtinRules).sanitizers[0]?.valid).toBe(true);
  });

  it('constant-argument: 第 1 引数が定数なら有効、変数なら無効', () => {
    const rules = rulesOf({
      sanitizers: [{ id: 'resolve', member: 'path.resolve', kinds: ['path'], validation: 'constant-argument' }],
    });
    const ok = annotate(graphOf([node('n1', "path.resolve('/srv/data', name)", { kind: 'call' })]), rules);
    const ng = annotate(graphOf([node('n2', 'path.resolve(name)', { kind: 'call' })]), rules);
    expect(ok.sanitizers[0]?.valid).toBe(true);
    expect(ng.sanitizers[0]?.valid).toBe(false);
    expect(ng.sanitizers[0]?.invalidReason).toContain('定数ではない');
  });

  it('呼び出し式でないノードは検証付きサニタイザとして有効にならない', () => {
    const rules = rulesOf({
      sanitizers: [{ id: 'escape', member: 'escapeHtml', kinds: ['html'], validation: 'none' }],
    });
    const result = annotate(graphOf([node('n1', 'escapeHtml')]), rules);
    expect(result.sanitizers[0]?.valid).toBe(true);
  });

  it('kinds が空のサニタイザはタグ語彙へ展開される', () => {
    const rules: ResolvedRuleSet = rulesOf({
      sources: [{ id: 's', member: 'req.query', kinds: ['sql'] }],
      sanitizers: [{ id: 'sanitize', call: 'sanitizeIt', kinds: [] }],
    });
    const resolved = resolveRuleSet({ ...rules });
    const result = annotate(graphOf([node('n1', 'sanitizeIt(value)', { kind: 'call' })]), resolved);
    expect(result.sanitizers[0]?.kinds).toEqual(['sql']);
  });
});

describe('annotate: シンクの確定', () => {
  it('SQL シンクは呼び出し名で一致し、taintedArgs は宣言どおり第 1 引数', () => {
    const graph = graphOf([node('n1', 'db.query(sql, params)', { kind: 'call' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['sql-query']);
    expect(result.sinks[0]?.taintedArgs).toEqual([0]);
    expect(result.sinks[0]?.severity).toBe('error');
    expect(result.sinks[0]?.cwe).toEqual(['CWE-89']);
  });

  it('引数が特定できない呼び出しでは taintedArgs を空（＝すべての引数）にする', () => {
    const rules = rulesOf({
      sinks: [{ id: 'any', call: 'sinkIt', kinds: ['sql'], severity: 'error', message: 'テスト用シンク' }],
    });
    const result = annotate(graphOf([node('n1', 'sinkIt', { kind: 'call' })]), rules);
    expect(result.sinks[0]?.taintedArgs).toEqual([]);
  });

  it('80 文字へ切り詰められた長い SQL でもサニタイザの検証が保たれる', () => {
    const sql = 'SELECT id, name FROM users WHERE id = ? AND tenant = ?';
    const line = `db.query('${sql}', [id, tenant])`;
    const truncated = `${line.slice(0, 80)}…`;
    const result = annotate(graphOf([node('n1', truncated, { kind: 'call' })]), builtinRules);
    expect(result.sanitizers[0]?.sanitizerId).toBe('sql-db-query');
    expect(result.sanitizers[0]?.valid).toBe(true);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['sql-query']);
  });

  it('taintedArgs を指定しないシンクは全引数を対象にする', () => {
    const rules = rulesOf({
      sinks: [{ id: 'all-args', call: 'sinkIt', kinds: ['sql'], severity: 'error', message: 'テスト用シンク' }],
    });
    const result = annotate(graphOf([node('n1', 'sinkIt(a, b, c)', { kind: 'call' })]), rules);
    expect(result.sinks[0]?.taintedArgs).toEqual([0, 1, 2]);
  });

  it('taintedArgs を指定したシンクはその位置だけを報告する', () => {
    const graph = graphOf([node('n1', 'net.connect(port, host)', { kind: 'call' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['ssrf-net-connect']);
    expect(result.sinks[0]?.taintedArgs).toEqual([1]);
  });

  it('接尾辞パターンのシンクはレシーバが違っても一致する', () => {
    const graph = graphOf([node('n1', 'document.body.innerHTML', { kind: 'property' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['xss-inner-html']);
  });

  it('member 付きのシンクが call のみのシンクより優先される', () => {
    const graph = graphOf([node('n1', 'db.exec(sql)', { kind: 'call' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['sql-db-exec']);
  });

  it('res.redirect はオープンリダイレクト 1 件だけになる', () => {
    const graph = graphOf([node('n1', 'res.redirect(req.query.next)', { kind: 'call' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['redirect-res']);
    expect(result.sinks[0]?.severity).toBe('warning');
  });

  it('シンクの message / advice / cwe が出現へ引き継がれる', () => {
    const graph = graphOf([node('n1', 'fs.readFile(userPath, cb)', { kind: 'call' })]);
    const sink = annotate(graph, builtinRules).sinks[0];
    expect(sink?.message).toContain('パストラバーサル');
    expect(sink?.advice).toContain('path.basename');
    expect(sink?.cwe).toEqual(['CWE-22']);
    expect(sink?.label).toBe('fs.readFile(userPath, cb)');
  });

  it('annotate の結果はルール定義の配列を共有しない', () => {
    const graph = graphOf([node('n1', 'db.query(sql)', { kind: 'call' })]);
    const sink = annotate(graph, builtinRules).sinks[0];
    const spec = builtinRules.sinkById.get('sql-query');
    expect(sink?.kinds).not.toBe(spec?.kinds);
    expect(sink?.kinds).toEqual(spec?.kinds);
  });
});

describe('annotate: require 別名の解決', () => {
  it('`const cp = require("child_process")` の別名を解決する', () => {
    const nodes = [
      node('n1', 'const cp = require("child_process")', { kind: 'assignment' }),
      node('n2', 'cp.exec(cmd)', { kind: 'call' }),
    ];
    const result = annotate(graphOf(nodes), builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['command-child-process-exec']);
    expect(result.sinks[0]?.nodeId).toBe('n2');
  });

  it('分割代入の require 別名を解決する', () => {
    const nodes = [
      node('n1', "const { exec } = require('child_process')", { kind: 'assignment' }),
      node('n2', 'exec(cmd)', { kind: 'call' }),
    ];
    const result = annotate(graphOf(nodes), builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['command-child-process-exec']);
  });

  it('別名ノード自体はシンクとして確定しない', () => {
    const nodes = [node('n1', 'const cp = require("child_process")', { kind: 'assignment' })];
    const result = annotate(graphOf(nodes), builtinRules);
    expect(result.sinks).toHaveLength(0);
    expect(result.sources).toHaveLength(0);
  });
});

describe('annotate: 式テキストの扱い', () => {
  it('text を label より優先して解析する', () => {
    const graph = graphOf([node('n1', 'db.query', { kind: 'call', text: 'db.query(sql)' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sinks.map((item) => item.sinkId)).toEqual(['sql-query']);
    expect(result.sanitizers[0]?.valid).toBe(false);
  });

  it('text が解析できなければ label へフォールバックする', () => {
    const graph = graphOf([node('n1', 'db.query(sql)', { kind: 'call', text: 'sql + id' })]);
    expect(annotate(graph, builtinRules).sinks.map((item) => item.sinkId)).toEqual(['sql-query']);
  });

  it('解析できない式には何も確定しない', () => {
    const graph = graphOf([node('n1', 'a + b', { kind: 'unknown' })]);
    const result = annotate(graph, builtinRules);
    expect(result.sources).toHaveLength(0);
    expect(result.sanitizers).toHaveLength(0);
    expect(result.sinks).toHaveLength(0);
  });

  it('関数が見つからないノードでも withinFunctions 無しの規則は適用される', () => {
    const graph = graphOf([node('n1', 'req.query.id', { functionId: 'missing::fn' })]);
    expect(annotate(graph, builtinRules).sources).toHaveLength(1);
  });
});

describe('annotate: パストラバーサルの回帰（benchmarks の代表例）', () => {
  /** 有効なサニタイザが落とせるタグの集合。 */
  const droppedKinds = (result: { readonly sanitizers: readonly { readonly nodeId: string; readonly valid: boolean; readonly kinds: readonly string[] }[] }, nodeIds: readonly string[]): Set<string> => {
    const dropped = new Set<string>();
    for (const occurrence of result.sanitizers) {
      if (!occurrence.valid || !nodeIds.includes(occurrence.nodeId)) continue;
      for (const kind of occurrence.kinds) dropped.add(kind);
    }
    return dropped;
  };

  it('vulnerable: `path.join` は無害化せず、fs.readFileSync が path シンクとして確定する', () => {
    // benchmarks/vulnerable/path-traversal-readfile.ts と同じ形
    const nodes = [
      node('n1', 'req.query.name'),
      node('n2', "path.join('/srv/files', name)", { kind: 'call' }),
      node('n3', "fs.readFileSync(target, 'utf8')", { kind: 'call' }),
    ];
    const result = annotate(graphOf(nodes), builtinRules);
    expect(result.sanitizers.filter((item) => item.nodeId === 'n2')).toEqual([]);
    expect(droppedKinds(result, ['n2']).has('path')).toBe(false);
    expect(result.sinks.filter((item) => item.nodeId === 'n3').map((item) => item.sinkId)).toEqual(['path-fs-read-file-sync']);
  });

  it('vulnerable: `path.resolve` も無害化しない', () => {
    const nodes = [
      node('n1', 'req.query.name'),
      node('n2', "path.resolve('/srv/files', name)", { kind: 'call' }),
      node('n3', "fs.readFile(target, 'utf8', cb)", { kind: 'call' }),
    ];
    const result = annotate(graphOf(nodes), builtinRules);
    expect(result.sanitizers.filter((item) => item.nodeId === 'n2')).toEqual([]);
    expect(droppedKinds(result, ['n2']).has('path')).toBe(false);
    expect(result.sinks.filter((item) => item.nodeId === 'n3').map((item) => item.sinkId)).toEqual(['path-fs-read-file']);
  });

  it('clean: `path.basename` は path タグを落とす有効なサニタイザになる', () => {
    // benchmarks/clean/path-basename.ts と同じ形
    const nodes = [
      node('n1', 'req.query.name'),
      node('n2', 'path.basename(req.query.name)', { kind: 'call' }),
      node('n3', "fs.readFileSync(path.join('/srv/files', safeName), 'utf8')", { kind: 'call' }),
    ];
    const result = annotate(graphOf(nodes), builtinRules);
    const basename = result.sanitizers.find((item) => item.nodeId === 'n2');
    expect(basename?.sanitizerId).toBe('path-basename');
    expect(basename?.valid).toBe(true);
    expect(basename?.kinds).toEqual(['path']);
    expect(droppedKinds(result, ['n2']).has('path')).toBe(true);
    // シンク自体は確定している（タグが落ちるかどうかは解析エンジンが判定する）
    expect(result.sinks.filter((item) => item.nodeId === 'n3').map((item) => item.sinkId)).toEqual(['path-fs-read-file-sync']);
  });
});

describe('annotate: 決定性と整形', () => {
  it('同じ入力に対して同じ結果を返し、nodeId → 規則 ID の順に並ぶ', () => {
    const nodes = [
      node('b#2', 'res.redirect(url)', { kind: 'call' }),
      node('a#1', 'db.query(sql)', { kind: 'call' }),
      node('c#3', 'el.innerHTML', { kind: 'property' }),
      node('d#4', 'req.query.id'),
    ];
    const graph = graphOf(nodes);
    const first = annotate(graph, builtinRules);
    const second = annotate(graph, builtinRules);
    expect(first).toEqual(second);
    const sinkIds = first.sinks.map((item) => `${item.nodeId}:${item.sinkId}`);
    expect(sinkIds).toEqual(['a#1:sql-query', 'b#2:redirect-res', 'c#3:xss-inner-html']);
    const sourceIds = first.sources.map((item) => item.nodeId);
    expect(sourceIds).toEqual(['d#4']);
  });

  it('空のグラフでは空の結果を返す', () => {
    const result = annotate(graphOf([]), builtinRules);
    expect(result).toEqual({ sources: [], sanitizers: [], sinks: [] });
  });

  it('annotateGraph はグラフと結果を束ねて返す', () => {
    const graph = graphOf([node('n1', 'req.query.id')]);
    const annotated = annotateGraph(graph, builtinRules);
    expect(annotated.graph).toBe(graph);
    expect(annotated.sources).toHaveLength(1);
    expect(annotated.sinks).toHaveLength(0);
  });
});
