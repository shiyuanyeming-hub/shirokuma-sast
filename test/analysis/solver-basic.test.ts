/**
 * 汚染伝播ソルバの基本テスト。
 * ソース → 伝播 → シンクの到達、タグ交差、`taintedArgs`、決定性、重複排除を固定する。
 */

import { describe, expect, it } from 'vitest';
import { analyze, solveGraph } from '../../src/analysis/solver.js';
import type { FlowKind, FlowNode } from '../../src/types.js';
import { at, makeAnalysis, makeEdge, makeFunction, makeNode, makeSink, makeSource, span } from './fixtures.js';

const FN = 'app.ts::handler';
const FILE = '/proj/app.ts';

/** `app.ts::handler` に属するノードを作る。 */
function node(index: number, kind: FlowKind, label: string, line: number): FlowNode {
  return makeNode({ id: `${FN}#${index}`, kind, functionId: FN, range: at(line), label });
}

/** 単純な「ソース → 代入 → シンク」のグラフ。 */
function directFlow() {
  return makeAnalysis({
    functions: [makeFunction({ id: FN, file: FILE })],
    nodes: [
      node(0, 'property', 'req.query.id', 3),
      node(1, 'local', 'sql', 4),
      node(2, 'call', 'db.query(sql)', 5),
    ],
    edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'assign'), makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0)],
    sources: [
      makeSource({
        nodeId: `${FN}#0`,
        sourceId: 'express.query',
        kinds: ['sql'],
        functionId: FN,
        range: at(3),
        label: 'req.query.id',
      }),
    ],
    sinks: [
      makeSink({
        nodeId: `${FN}#2`,
        sinkId: 'sql-injection',
        functionId: FN,
        range: at(5),
        kinds: ['sql'],
        cwe: ['CWE-89'],
        message: 'SQL インジェクションの可能性があります',
        advice: 'プレースホルダを使ってください',
        label: 'db.query(sql)',
        taintedArgs: [0],
      }),
    ],
  });
}

describe('analyze: 到達と検出', () => {
  it('ソース → 代入 → シンクの到達を検出する', () => {
    const { graph, rules } = directFlow();
    const result = analyze(graph, rules);

    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0];
    expect(finding?.ruleId).toBe('sql-injection');
    expect(finding?.severity).toBe('error');
    expect(finding?.message).toBe('SQL インジェクションの可能性があります');
    expect(finding?.advice).toBe('プレースホルダを使ってください');
    expect(finding?.cwe).toEqual(['CWE-89']);
    expect(finding?.kinds).toEqual(['sql']);
    expect(finding?.sourceId).toBe('express.query');
    expect(finding?.sinkId).toBe('sql-injection');
    expect(finding?.file).toBe(FILE);
    expect(finding?.relativePath).toBe('app.ts');
    expect(finding?.functionId).toBe(FN);
    expect(finding?.range).toEqual(at(5));
  });

  it('proof が source → propagate → sink の順に実経路を反映する', () => {
    const { graph, rules } = directFlow();
    const finding = analyze(graph, rules).findings[0];

    expect(finding?.proof.map((step) => step.role)).toEqual(['source', 'propagate', 'sink']);
    expect(finding?.proof.map((step) => step.nodeId)).toEqual([`${FN}#0`, `${FN}#1`, `${FN}#2`]);
    expect(finding?.proof.map((step) => step.label)).toEqual(['req.query.id', 'sql', 'db.query(sql)']);
    for (const step of finding?.proof ?? []) {
      expect(step.file).toBe(FILE);
      expect(step.range.start.line).toBeGreaterThan(0);
    }
  });

  it('シンクに到達しなければ検出しない', () => {
    const { graph, rules } = directFlow();
    const noSink = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(1, 'local', 'sql', 4)],
      edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'assign')],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN }),
      ],
      sinks: [],
    });
    expect(analyze(graph, rules).findings).toHaveLength(1);
    expect(analyze(noSink.graph, noSink.rules).findings).toHaveLength(0);
  });

  it('ソースが無ければ何も検出しない', () => {
    const fixture = directFlow();
    const withoutSource = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(1, 'local', 'sql', 4), node(2, 'call', 'db.query(sql)', 5)],
      edges: [makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0)],
      sinks: [makeSink({ nodeId: `${FN}#2`, sinkId: 'sql-injection', functionId: FN, range: at(5) })],
    });
    expect(analyze(fixture.graph, fixture.rules).findings).toHaveLength(1);
    expect(analyze(withoutSource.graph, withoutSource.rules).findings).toHaveLength(0);
  });
});

describe('analyze: タグと引数の絞り込み', () => {
  it('タグの交差が空なら報告しない', () => {
    const { graph, rules } = directFlow();
    const htmlSink = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(2, 'call', 'res.send(sql)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 0)],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN }),
      ],
      sinks: [
        makeSink({ nodeId: `${FN}#2`, sinkId: 'xss', functionId: FN, kinds: ['html'], range: at(5) }),
      ],
    });

    expect(analyze(graph, rules).findings).toHaveLength(1);
    expect(analyze(htmlSink.graph, htmlSink.rules).findings).toHaveLength(0);
  });

  it('finding.kinds はトークンとシンクのタグの交差になる', () => {
    const multi = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(2, 'call', 'db.query(sql)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 0)],
      sources: [
        makeSource({
          nodeId: `${FN}#0`,
          sourceId: 'express.query',
          kinds: ['sql', 'html', 'command'],
          functionId: FN,
        }),
      ],
      sinks: [
        makeSink({ nodeId: `${FN}#2`, sinkId: 'sql-injection', functionId: FN, kinds: ['sql'], range: at(5) }),
      ],
    });

    const finding = analyze(multi.graph, multi.rules).findings[0];
    expect(finding?.kinds).toEqual(['sql']);
  });

  it('taintedArgs に含まれない引数位置からの到達は報告しない', () => {
    const { graph, rules } = directFlow();
    const secondArg = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(2, 'call', 'child_process.exec(cmd, opts)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 0)],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['command'], functionId: FN }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'command-injection',
          functionId: FN,
          kinds: ['command'],
          range: at(5),
          taintedArgs: [1],
        }),
      ],
    });

    expect(analyze(graph, rules).findings).toHaveLength(1);
    expect(analyze(secondArg.graph, secondArg.rules).findings).toHaveLength(0);
  });

  it('taintedArgs に含まれる引数位置からの到達は報告する', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(2, 'call', 'child_process.exec(cmd, opts)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 1)],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['command'], functionId: FN }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'command-injection',
          functionId: FN,
          kinds: ['command'],
          range: at(5),
          taintedArgs: [0, 1],
        }),
      ],
    });

    const findings = analyze(fixture.graph, fixture.rules).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]?.id).toBe('command-injection:app.ts:5:1');
  });

  it('taintedArgs が空配列ならすべての引数を許容する', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(2, 'call', 'eval(code)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 2)],
      sources: [makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['code'], functionId: FN })],
      sinks: [
        makeSink({ nodeId: `${FN}#2`, sinkId: 'code-injection', functionId: FN, kinds: ['code'], range: at(5) }),
      ],
    });

    expect(analyze(fixture.graph, fixture.rules).findings).toHaveLength(1);
  });

  it('引数位置を特定できない到達は taintedArgs 指定時に報告しない', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(2, 'call', 'db.query(sql)', 5)],
      // `argument` 辺ではなく `property` 辺で届く（引数位置が不明な経路）。
      edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'property')],
      sources: [makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN })],
      sinks: [
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'sql-injection',
          functionId: FN,
          kinds: ['sql'],
          range: at(5),
          taintedArgs: [0],
        }),
      ],
    });

    expect(analyze(fixture.graph, fixture.rules).findings).toHaveLength(0);
  });

  it('プロパティ代入のシンクは引数位置の指定に関わらず報告する', () => {
    // `node.innerHTML = '<h1>' + nickname + '</h1>'` は呼び出しではないため、
    // `taintedArgs: [0]`（呼び出しの第 1 引数）を適用してはいけない。
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'local', 'nickname', 7), node(1, 'property', 'node.innerHTML', 8)],
      edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'property')],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['html'], functionId: FN, range: at(7) }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#1`,
          sinkId: 'xss-inner-html',
          functionId: FN,
          kinds: ['html'],
          range: at(8),
          label: 'node.innerHTML',
          taintedArgs: [0],
        }),
      ],
    });

    const findings = analyze(fixture.graph, fixture.rules).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('xss-inner-html');
    expect(findings[0]?.proof.map((step) => step.role)).toEqual(['source', 'sink']);
  });
});

describe('analyze: 決定性と重複排除', () => {
  it('検出順がファイル → 行 → 列 → ruleId で決定的になる', () => {
    const a = 'a.ts::f';
    const b = 'b.ts::g';
    const fixture = makeAnalysis({
      functions: [
        makeFunction({ id: a, file: '/proj/a.ts' }),
        makeFunction({ id: b, file: '/proj/b.ts' }),
      ],
      nodes: [
        makeNode({ id: `${a}#0`, kind: 'property', functionId: a, range: at(9), label: 'req.query.x' }),
        makeNode({ id: `${a}#1`, kind: 'call', functionId: a, range: at(10), label: 'db.query(x)' }),
        makeNode({ id: `${a}#2`, kind: 'call', functionId: a, range: at(4), label: 'eval(x)' }),
        makeNode({ id: `${b}#0`, kind: 'property', functionId: b, range: at(2), label: 'req.query.y' }),
        makeNode({ id: `${b}#1`, kind: 'call', functionId: b, range: at(3), label: 'db.query(y)' }),
      ],
      edges: [
        makeEdge(`${a}#0`, `${a}#1`, 'argument', 0),
        makeEdge(`${a}#0`, `${a}#2`, 'argument', 0),
        makeEdge(`${b}#0`, `${b}#1`, 'argument', 0),
      ],
      sources: [
        makeSource({ nodeId: `${b}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: b, range: at(2) }),
        makeSource({ nodeId: `${a}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: a, range: at(9) }),
      ],
      sinks: [
        makeSink({ nodeId: `${a}#1`, sinkId: 'sql-injection', functionId: a, kinds: ['sql'], range: at(10) }),
        makeSink({ nodeId: `${a}#2`, sinkId: 'code-injection', functionId: a, kinds: ['sql'], range: at(4) }),
        makeSink({ nodeId: `${b}#1`, sinkId: 'sql-injection', functionId: b, kinds: ['sql'], range: at(3) }),
      ],
    });

    const findings = analyze(fixture.graph, fixture.rules).findings;
    expect(findings.map((finding) => `${finding.relativePath}:${finding.range.start.line}:${finding.ruleId}`)).toEqual([
      'a.ts:4:code-injection',
      'a.ts:10:sql-injection',
      'b.ts:3:sql-injection',
    ]);
    // 同じ入力に対して常に同じ順序・同じ ID を返す。
    expect(analyze(fixture.graph, fixture.rules).findings.map((finding) => finding.id)).toEqual(
      findings.map((finding) => finding.id),
    );
  });

  it('Finding.id は <ruleId>:<relativePath>:<line>:<column> 形式になる', () => {
    const { graph, rules } = directFlow();
    const finding = analyze(graph, rules).findings[0];
    expect(finding?.id).toBe('sql-injection:app.ts:5:1');
    expect(finding?.id).toBe(`${finding?.ruleId}:${finding?.relativePath}:5:1`);
  });

  it('同一 (ruleId, ファイル, 範囲) の検出は既定で 1 件に畳まれる', () => {
    const fixture = twoSourcesToOneSink();
    const findings = analyze(fixture.graph, fixture.rules).findings;
    expect(findings).toHaveLength(1);
  });

  it('dedupe: false なら同一シンクへの複数経路をすべて報告する', () => {
    const fixture = twoSourcesToOneSink();
    const outcome = solveGraph(fixture.graph, fixture.rules, { dedupe: false });
    expect(outcome.findings).toHaveLength(2);
    expect(new Set(outcome.findings.map((finding) => finding.sourceId))).toEqual(
      new Set(['express.query', 'express.body']),
    );
  });

  it('同一ノード・同一 ruleId の重複したシンク出現は 1 件に畳まれる', () => {
    const fixture = twoSourcesToOneSink();
    // 同じ ruleId のシンク出現を同一ノードへ二重に置いても、検出は 1 件。
    const duplicated = makeAnalysis({
      functions: fixture.graph.graph.functions,
      nodes: fixture.graph.graph.nodes,
      edges: fixture.graph.graph.edges,
      sources: fixture.graph.sources,
      sinks: [...fixture.graph.sinks, ...fixture.graph.sinks],
    });

    const findings = analyze(duplicated.graph, duplicated.rules).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]?.ruleId).toBe('sql-injection');
  });

  it('同一ノードでも ruleId が違えば両方を報告する', () => {
    const fixture = twoSourcesToOneSink();
    const multiRule = makeAnalysis({
      functions: fixture.graph.graph.functions,
      nodes: fixture.graph.graph.nodes,
      edges: fixture.graph.graph.edges,
      sources: fixture.graph.sources,
      sinks: [
        ...fixture.graph.sinks,
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'code-injection',
          functionId: FN,
          kinds: ['sql'],
          range: at(5),
          taintedArgs: [0],
        }),
      ],
    });

    const findings = analyze(multiRule.graph, multiRule.rules).findings;
    expect(findings.map((finding) => finding.ruleId)).toEqual(['code-injection', 'sql-injection']);
  });

  it('入れ子の式に二重に付いた同一シンクは広い範囲だけを報告する', () => {
    // `const response = await axios.get(endpoint);` のように、annotate が
    // 呼び出し式とそれを包む式の両方へ同じシンク規則を出現させる形。
    const nested = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [
        node(0, 'property', 'req.query.url', 7),
        node(1, 'local', 'endpoint', 7),
        makeNode({
          id: `${FN}#2`,
          kind: 'call',
          functionId: FN,
          range: span(8, 26, 8, 45),
          label: 'axios.get(endpoint)',
        }),
        makeNode({
          id: `${FN}#3`,
          kind: 'unknown',
          functionId: FN,
          range: span(8, 20, 8, 45),
          label: 'await axios.get(endpoint)',
        }),
      ],
      edges: [
        makeEdge(`${FN}#0`, `${FN}#1`, 'assign'),
        makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0),
        makeEdge(`${FN}#2`, `${FN}#3`, 'assign'),
      ],
      sources: [
        makeSource({
          nodeId: `${FN}#0`,
          sourceId: 'express.query',
          kinds: ['url'],
          functionId: FN,
          range: at(7, 20),
        }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'ssrf-axios-get',
          functionId: FN,
          kinds: ['url'],
          range: span(8, 26, 8, 45),
          label: 'axios.get(endpoint)',
          taintedArgs: [0],
        }),
        makeSink({
          nodeId: `${FN}#3`,
          sinkId: 'ssrf-axios-get',
          functionId: FN,
          kinds: ['url'],
          range: span(8, 20, 8, 45),
          label: 'await axios.get(endpoint)',
          taintedArgs: [0],
        }),
      ],
    });

    const findings = analyze(nested.graph, nested.rules).findings;
    expect(findings).toHaveLength(1);
    // 残るのは広い方（`await axios.get(...)`）で、証明も呼び出し全体を含む。
    expect(findings[0]?.range).toEqual(span(8, 20, 8, 45));
    expect(findings[0]?.proof.map((step) => step.nodeId)).toEqual([
      `${FN}#0`,
      `${FN}#1`,
      `${FN}#2`,
      `${FN}#3`,
    ]);

    // `dedupe: false` では畳まずに両方を返す。
    expect(solveGraph(nested.graph, nested.rules, { dedupe: false }).findings).toHaveLength(2);
  });

  it('同じ行にある別々のシンクは包含関係が無ければ両方を報告する', () => {
    const sameLine = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [
        makeNode({ id: `${FN}#0`, kind: 'property', functionId: FN, range: at(5), label: 'req.query.id' }),
        makeNode({ id: `${FN}#1`, kind: 'call', functionId: FN, range: span(5, 1, 5, 5), label: 'f(req.query.id)' }),
        makeNode({ id: `${FN}#2`, kind: 'call', functionId: FN, range: span(5, 8, 5, 12), label: 'g(req.query.id)' }),
      ],
      edges: [
        makeEdge(`${FN}#0`, `${FN}#1`, 'argument', 0),
        makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 0),
      ],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#1`,
          sinkId: 'sql-injection',
          functionId: FN,
          kinds: ['sql'],
          range: span(5, 1, 5, 5),
          taintedArgs: [0],
        }),
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'sql-injection',
          functionId: FN,
          kinds: ['sql'],
          range: span(5, 8, 5, 12),
          taintedArgs: [0],
        }),
      ],
    });

    const findings = analyze(sameLine.graph, sameLine.rules).findings;
    expect(findings).toHaveLength(2);
    expect(findings.map((finding) => finding.range.start.column)).toEqual([1, 8]);
  });

  it('ルールセットに存在しない sinkId の出現は無視する', () => {
    const { graph, rules } = directFlow();
    const known = analyze(graph, rules).findings;
    expect(known).toHaveLength(1);

    const empty = solveGraph(graph, { ...rules, sinks: [], sinkById: new Map() }, {});
    expect(empty.findings).toHaveLength(0);
  });
});

describe('analyze: 統計と契約', () => {
  it('stats がグラフ規模と反復回数を報告する', () => {
    const { graph, rules } = directFlow();
    const { stats } = analyze(graph, rules);

    expect(stats.filesScanned).toBe(1);
    expect(stats.functionsAnalysed).toBe(1);
    expect(stats.flowNodes).toBe(3);
    expect(stats.flowEdges).toBe(2);
    expect(stats.iterations).toBeGreaterThan(0);
    expect(stats.truncated).toEqual([]);
  });

  it('analyze は契約どおり findings と stats だけを返す', () => {
    const { graph, rules } = directFlow();
    const result = analyze(graph, rules);
    expect(Object.keys(result).sort()).toEqual(['findings', 'stats']);
  });

  it('solveGraph の diagnostics は常に配列で返る', () => {
    const { graph, rules } = directFlow();
    expect(Array.isArray(solveGraph(graph, rules).diagnostics)).toBe(true);
    expect(solveGraph(graph, rules, { maxIterationsPerFunction: 100 }).diagnostics).toEqual([]);
  });

  it('反復上限を超えると打ち切り、stats.truncated と診断に記録する', () => {
    const chain = Array.from({ length: 8 }, (_, index) =>
      makeNode({
        id: `${FN}#${index}`,
        kind: index === 0 ? 'property' : 'local',
        functionId: FN,
        range: at(index + 1),
        label: `v${index}`,
      }),
    );
    const edges = chain
      .slice(0, -1)
      .map((_, index) => makeEdge(`${FN}#${index}`, `${FN}#${index + 1}`, 'assign'));

    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: chain,
      edges,
      sources: [makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN })],
      sinks: [
        makeSink({ nodeId: `${FN}#7`, sinkId: 'sql-injection', functionId: FN, kinds: ['sql'], range: at(8) }),
      ],
    });

    const full = analyze(fixture.graph, fixture.rules);
    expect(full.findings).toHaveLength(1);
    expect(full.stats.truncated).toEqual([]);

    const bounded = solveGraph(fixture.graph, fixture.rules, { maxIterationsPerFunction: 3 });
    expect(bounded.findings).toHaveLength(0);
    expect(bounded.stats.truncated).toEqual([FN]);
    expect(bounded.diagnostics.length).toBeGreaterThan(0);
    expect(bounded.diagnostics[0]?.level).toBe('warning');
    expect(bounded.diagnostics[0]?.file).toBe(FILE);
  });

  it('kinds の許可リストで報告タグを絞り込める', () => {
    const { graph, rules } = directFlow();
    expect(solveGraph(graph, rules, { kinds: ['sql'] }).findings).toHaveLength(1);
    expect(solveGraph(graph, rules, { kinds: ['html'] }).findings).toHaveLength(0);
  });

  it('グラフに存在しないノードを指す出現は無視して落ちない', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(2, 'call', 'db.query(sql)', 5)],
      edges: [],
      sources: [makeSource({ nodeId: `${FN}#99`, sourceId: 'express.query', kinds: ['sql'], functionId: FN })],
      sinks: [makeSink({ nodeId: `${FN}#2`, sinkId: 'sql-injection', functionId: FN, kinds: ['sql'], range: at(5) })],
    });

    expect(analyze(fixture.graph, fixture.rules).findings).toHaveLength(0);
  });
});

/** 2 つのソースが同じシンクへ到達するグラフ。 */
function twoSourcesToOneSink() {
  return makeAnalysis({
    functions: [makeFunction({ id: FN, file: FILE })],
    nodes: [
      node(0, 'property', 'req.query.id', 3),
      node(1, 'property', 'req.body.id', 4),
      node(2, 'call', 'db.query(sql)', 5),
    ],
    edges: [makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 0), makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0)],
    sources: [
      makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN, range: at(3) }),
      makeSource({ nodeId: `${FN}#1`, sourceId: 'express.body', kinds: ['sql'], functionId: FN, range: at(4) }),
    ],
    sinks: [
      makeSink({
        nodeId: `${FN}#2`,
        sinkId: 'sql-injection',
        functionId: FN,
        kinds: ['sql'],
        range: at(5),
        taintedArgs: [0],
      }),
    ],
  });
}
