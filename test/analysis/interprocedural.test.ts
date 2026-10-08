/**
 * 関数間伝播（引数 → 戻り値、引数 → シンク）と再帰のテスト。
 *
 * IR 構築が関数横断辺（引数式 → 仮引数、return → 呼び出しノード）を張る形と、
 * 呼び出し解決情報だけを頼りにソルバが補助辺を合成する形の両方を固定する。
 */

import { describe, expect, it } from 'vitest';
import type { AnnotatedGraph } from '../../src/rules/annotate-contract.js';
import { analyze, solveGraph } from '../../src/analysis/solver.js';
import { buildSummaryTable, summarizeFunction } from '../../src/analysis/summary.js';
import type { CallSite, FlowEdge, FlowNode, FunctionIR, ResolvedRuleSet } from '../../src/types.js';
import {
  at,
  makeAnalysis,
  makeCallSite,
  makeEdge,
  makeFunction,
  makeNode,
  makeParam,
  makeSanitizer,
  makeSink,
  makeSource,
} from './fixtures.js';

const HANDLER = 'app.ts::handler';
const HELPER = 'app.ts::id';
const FILE = '/proj/app.ts';

/** 解析フィクスチャのうち解析に必要な部分。 */
interface CallChainFixture {
  readonly graph: AnnotatedGraph;
  readonly rules: ResolvedRuleSet;
}

/**
 * `handler(req.query.id)` が `id(x)` を呼び、戻り値を `db.query` へ渡すグラフ。
 * `shape: 'explicit'` は IR が関数横断辺を張る形、`'resolved'` は
 * 呼び出し解決情報だけがある形（ソルバが補助辺を合成する）。
 */
function callChain(shape: 'explicit' | 'resolved'): CallChainFixture {
  const functions: FunctionIR[] = [
    makeFunction({ id: HANDLER, file: FILE, callees: [HELPER], range: at(1) }),
    makeFunction({ id: HELPER, file: FILE, params: [makeParam('x', 0)], range: at(1) }),
  ];
  const nodes: FlowNode[] = [
    makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(3), label: 'req.query.id' }),
    makeNode({
      id: `${HANDLER}#1`,
      kind: 'call',
      functionId: HANDLER,
      range: at(4),
      label: 'id(req.query.id)',
      resolvedCallees: [HELPER],
    }),
    makeNode({ id: `${HELPER}#0`, kind: 'param', functionId: HELPER, range: at(1), label: 'x' }),
    makeNode({ id: `${HELPER}#1`, kind: 'return', functionId: HELPER, range: at(2), label: 'x' }),
    makeNode({ id: `${HANDLER}#2`, kind: 'call', functionId: HANDLER, range: at(5), label: 'db.query(sql)' }),
  ];

  const edges: FlowEdge[] =
    shape === 'explicit'
      ? [
          makeEdge(`${HANDLER}#0`, `${HELPER}#0`, 'argument', 0),
          makeEdge(`${HELPER}#0`, `${HELPER}#1`, 'assign'),
          makeEdge(`${HELPER}#1`, `${HANDLER}#1`, 'return'),
          makeEdge(`${HANDLER}#1`, `${HANDLER}#2`, 'argument', 0),
        ]
      : [
          makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
          makeEdge(`${HELPER}#0`, `${HELPER}#1`, 'assign'),
          makeEdge(`${HANDLER}#1`, `${HANDLER}#2`, 'argument', 0),
        ];

  const callSites: CallSite[] = [
    makeCallSite(`${HANDLER}#1`, HANDLER, [HELPER], 'id(req.query.id)', at(4)),
  ];

  return makeAnalysis({
    functions,
    nodes,
    edges,
    callSites,
    sources: [
      makeSource({
        nodeId: `${HANDLER}#0`,
        sourceId: 'express.query',
        kinds: ['sql'],
        functionId: HANDLER,
        range: at(3),
        label: 'req.query.id',
      }),
    ],
    sinks: [
      makeSink({
        nodeId: `${HANDLER}#2`,
        sinkId: 'sql-injection',
        functionId: HANDLER,
        kinds: ['sql'],
        range: at(5),
        label: 'db.query(sql)',
        taintedArgs: [0],
      }),
    ],
  });
}

/**
 * `a(x)` ⇄ `b(y)` の相互再帰。`a` の引数が `b` を経由して `a` のシンクへ戻る。
 * 形状は「呼び出し解決情報だけ」（ソルバが仮引数への補助辺を合成する）。
 */
function mutualRecursion(): CallChainFixture {
  const a = 'app.ts::a';
  const b = 'app.ts::b';
  return makeAnalysis({
    functions: [
      makeFunction({ id: a, file: FILE, params: [makeParam('x', 0)], callees: [b], range: at(1) }),
      makeFunction({ id: b, file: FILE, params: [makeParam('y', 0)], callees: [a], range: at(1) }),
    ],
    nodes: [
      makeNode({ id: `${a}#0`, kind: 'param', functionId: a, range: at(1), label: 'x' }),
      makeNode({ id: `${a}#1`, kind: 'call', functionId: a, range: at(3), label: 'b(x)', resolvedCallees: [b] }),
      makeNode({ id: `${a}#2`, kind: 'return', functionId: a, range: at(4), label: 'x' }),
      makeNode({ id: `${a}#3`, kind: 'call', functionId: a, range: at(5), label: 'db.query(x)' }),
      makeNode({ id: `${a}#4`, kind: 'property', functionId: a, range: at(2), label: 'req.query.q' }),
      makeNode({ id: `${b}#0`, kind: 'param', functionId: b, range: at(1), label: 'y' }),
      makeNode({ id: `${b}#1`, kind: 'call', functionId: b, range: at(3), label: 'a(y)', resolvedCallees: [a] }),
      makeNode({ id: `${b}#2`, kind: 'return', functionId: b, range: at(4), label: 'y' }),
    ],
    edges: [
      makeEdge(`${a}#4`, `${a}#1`, 'argument', 0),
      makeEdge(`${a}#0`, `${a}#1`, 'argument', 0),
      makeEdge(`${a}#0`, `${a}#3`, 'argument', 0),
      makeEdge(`${a}#0`, `${a}#2`, 'assign'),
      makeEdge(`${b}#0`, `${b}#1`, 'argument', 0),
      makeEdge(`${b}#0`, `${b}#2`, 'assign'),
    ],
    sources: [
      makeSource({ nodeId: `${a}#4`, sourceId: 'express.query', kinds: ['sql'], functionId: a, range: at(2) }),
    ],
    sinks: [
      makeSink({
        nodeId: `${a}#3`,
        sinkId: 'sql-injection',
        functionId: a,
        kinds: ['sql'],
        range: at(5),
        taintedArgs: [0],
      }),
    ],
  });
}

describe('関数間伝播: 引数 → 戻り値 → シンク', () => {
  it('IR が関数横断辺を張る形でも検出し、証明が関数をまたぐ', () => {
    const { graph, rules } = callChain('explicit');
    const findings = analyze(graph, rules).findings;

    expect(findings).toHaveLength(1);
    const proof = findings[0]?.proof ?? [];
    expect(proof.map((step) => step.nodeId)).toEqual([
      `${HANDLER}#0`,
      `${HELPER}#0`,
      `${HELPER}#1`,
      `${HANDLER}#1`,
      `${HANDLER}#2`,
    ]);
    expect(proof.map((step) => step.role)).toEqual(['source', 'propagate', 'propagate', 'propagate', 'sink']);
    expect(proof.every((step) => step.file === FILE)).toBe(true);
  });

  it('呼び出し解決情報だけがある形でも補助辺を合成して同じ検出を返す', () => {
    const explicit = callChain('explicit');
    const resolved = callChain('resolved');

    const explicitFindings = analyze(explicit.graph, explicit.rules).findings;
    const resolvedFindings = analyze(resolved.graph, resolved.rules).findings;

    expect(resolvedFindings).toHaveLength(1);
    expect(resolvedFindings[0]?.ruleId).toBe(explicitFindings[0]?.ruleId);
    expect(resolvedFindings[0]?.range).toEqual(explicitFindings[0]?.range);
    expect(resolvedFindings[0]?.id).toBe(explicitFindings[0]?.id);
    expect(resolvedFindings[0]?.proof[0]?.role).toBe('source');
    expect(resolvedFindings[0]?.proof.at(-1)?.role).toBe('sink');
  });

  it('呼び出し先の中にあるシンクへ補助辺の合成で到達する', () => {
    // 呼び出し先 `id(x)` の本体がシンクを持つ形。仮引数への補助辺を
    // 合成しなければトークンは呼び出しノードで止まり、検出できない。
    const fixture = makeAnalysis({
      functions: [
        makeFunction({ id: HANDLER, file: FILE, callees: [HELPER], range: at(1) }),
        makeFunction({ id: HELPER, file: FILE, params: [makeParam('x', 0)], range: at(1) }),
      ],
      nodes: [
        makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(3), label: 'req.query.id' }),
        makeNode({
          id: `${HANDLER}#1`,
          kind: 'call',
          functionId: HANDLER,
          range: at(4),
          label: 'id(req.query.id)',
          resolvedCallees: [HELPER],
        }),
        makeNode({ id: `${HELPER}#0`, kind: 'param', functionId: HELPER, range: at(1), label: 'x' }),
        makeNode({ id: `${HELPER}#1`, kind: 'call', functionId: HELPER, range: at(2), label: 'db.query(x)' }),
      ],
      edges: [
        makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
        makeEdge(`${HELPER}#0`, `${HELPER}#1`, 'argument', 0),
      ],
      sources: [
        makeSource({ nodeId: `${HANDLER}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: HANDLER }),
      ],
      sinks: [
        makeSink({
          nodeId: `${HELPER}#1`,
          sinkId: 'sql-injection',
          functionId: HELPER,
          kinds: ['sql'],
          range: at(2),
          taintedArgs: [0],
        }),
      ],
    });

    const findings = analyze(fixture.graph, fixture.rules).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]?.proof.map((step) => step.nodeId)).toEqual([
      `${HANDLER}#0`,
      `${HANDLER}#1`,
      `${HELPER}#0`,
      `${HELPER}#1`,
    ]);
    expect(findings[0]?.proof.map((step) => step.role)).toEqual(['source', 'propagate', 'propagate', 'sink']);
  });

  it('引数位置が違う呼び出しでは対応する仮引数へ流す', () => {
    const build = (argIndex: number) =>
      makeAnalysis({
        functions: [
          makeFunction({ id: HANDLER, file: FILE, callees: [HELPER], range: at(1) }),
          makeFunction({ id: HELPER, file: FILE, params: [makeParam('a', 0), makeParam('b', 1)] }),
        ],
        nodes: [
          makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(3), label: 'req.query.id' }),
          makeNode({
            id: `${HANDLER}#1`,
            kind: 'call',
            functionId: HANDLER,
            range: at(4),
            label: 'id(clean, req.query.id)',
            resolvedCallees: [HELPER],
          }),
          makeNode({ id: `${HELPER}#0`, kind: 'param', functionId: HELPER, range: at(1), label: 'a' }),
          makeNode({ id: `${HELPER}#1`, kind: 'param', functionId: HELPER, range: at(1), label: 'b' }),
          makeNode({ id: `${HELPER}#2`, kind: 'call', functionId: HELPER, range: at(2), label: 'db.query(b)' }),
        ],
        edges: [
          makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', argIndex),
          makeEdge(`${HELPER}#1`, `${HELPER}#2`, 'argument', 0),
        ],
        sources: [
          makeSource({
            nodeId: `${HANDLER}#0`,
            sourceId: 'express.query',
            kinds: ['sql'],
            functionId: HANDLER,
            range: at(3),
          }),
        ],
        sinks: [
          makeSink({
            nodeId: `${HELPER}#2`,
            sinkId: 'sql-injection',
            functionId: HELPER,
            kinds: ['sql'],
            range: at(2),
            taintedArgs: [0],
          }),
        ],
      });

    const secondArg = build(1);
    const firstArg = build(0);
    expect(analyze(secondArg.graph, secondArg.rules).findings).toHaveLength(1);
    expect(analyze(firstArg.graph, firstArg.rules).findings).toHaveLength(0);
  });

  it('呼び出しが未解決でも IR の直結辺があれば伝播する', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: HANDLER, file: FILE })],
      nodes: [
        makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(3), label: 'req.query.id' }),
        makeNode({ id: `${HANDLER}#1`, kind: 'call', functionId: HANDLER, range: at(4), label: 'unknown(req.query.id)' }),
        makeNode({ id: `${HANDLER}#2`, kind: 'call', functionId: HANDLER, range: at(5), label: 'db.query(x)' }),
      ],
      edges: [
        makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
        makeEdge(`${HANDLER}#1`, `${HANDLER}#2`, 'argument', 0),
      ],
      sources: [
        makeSource({ nodeId: `${HANDLER}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: HANDLER }),
      ],
      sinks: [
        makeSink({
          nodeId: `${HANDLER}#2`,
          sinkId: 'sql-injection',
          functionId: HANDLER,
          kinds: ['sql'],
          range: at(5),
          taintedArgs: [0],
        }),
      ],
    });

    expect(analyze(fixture.graph, fixture.rules).findings).toHaveLength(1);
  });
});

describe('再帰と相互再帰', () => {
  it('自己再帰は不動点で停止し、シンクを 1 件だけ報告する', () => {
    const LOOP = 'app.ts::loop';
    const fixture = makeAnalysis({
      functions: [
        makeFunction({ id: LOOP, file: FILE, params: [makeParam('x', 0)], callees: [LOOP], range: at(1) }),
      ],
      nodes: [
        makeNode({ id: `${LOOP}#0`, kind: 'param', functionId: LOOP, range: at(1), label: 'x' }),
        makeNode({
          id: `${LOOP}#1`,
          kind: 'call',
          functionId: LOOP,
          range: at(3),
          label: 'loop(x)',
          resolvedCallees: [LOOP],
        }),
        makeNode({ id: `${LOOP}#2`, kind: 'return', functionId: LOOP, range: at(4), label: 'x' }),
        makeNode({ id: `${LOOP}#3`, kind: 'call', functionId: LOOP, range: at(5), label: 'db.query(x)' }),
        makeNode({ id: `${LOOP}#4`, kind: 'property', functionId: LOOP, range: at(2), label: 'req.query.q' }),
      ],
      edges: [
        makeEdge(`${LOOP}#4`, `${LOOP}#1`, 'argument', 0),
        makeEdge(`${LOOP}#0`, `${LOOP}#1`, 'argument', 0),
        makeEdge(`${LOOP}#0`, `${LOOP}#3`, 'argument', 0),
        makeEdge(`${LOOP}#0`, `${LOOP}#2`, 'assign'),
      ],
      sources: [
        makeSource({ nodeId: `${LOOP}#4`, sourceId: 'express.query', kinds: ['sql'], functionId: LOOP, range: at(2) }),
      ],
      sinks: [
        makeSink({
          nodeId: `${LOOP}#3`,
          sinkId: 'sql-injection',
          functionId: LOOP,
          kinds: ['sql'],
          range: at(5),
          taintedArgs: [0],
        }),
      ],
    });

    const result = analyze(fixture.graph, fixture.rules);
    expect(result.findings).toHaveLength(1);
    expect(result.stats.truncated).toEqual([]);
    expect(result.stats.iterations).toBeLessThan(50);
  });

  it('相互再帰でも停止し、再入した関数内のシンクを報告する', () => {
    const fixture = mutualRecursion();
    const result = analyze(fixture.graph, fixture.rules);

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0]?.ruleId).toBe('sql-injection');
    expect(result.findings[0]?.functionId).toBe('app.ts::a');
    expect(result.stats.truncated).toEqual([]);
    expect(result.stats.iterations).toBeLessThan(100);
  });

  it('反復上限を下げると相互再帰は打ち切られ、stats.truncated に記録される', () => {
    const fixture = mutualRecursion();
    const outcome = solveGraph(fixture.graph, fixture.rules, { maxIterationsPerFunction: 2 });

    expect(outcome.stats.truncated.length).toBeGreaterThan(0);
    expect(outcome.stats.truncated).toContain('app.ts::a');
    expect(outcome.diagnostics.some((diagnostic) => diagnostic.level === 'warning')).toBe(true);
  });

  it('再帰の展開上限（maxCallDepth）で再入を打ち切っても検出は壊れない', () => {
    const fixture = mutualRecursion();
    const limited = solveGraph(fixture.graph, fixture.rules, { maxCallDepth: 1 });
    const unlimited = solveGraph(fixture.graph, fixture.rules, { maxCallDepth: 0 });

    expect(limited.findings).toHaveLength(1);
    expect(unlimited.findings).toHaveLength(1);
    expect(limited.stats.truncated).toEqual([]);
  });
});

describe('サマリ', () => {
  it('引数 → 戻り値の関係を taintedReturnFromParams に記録する', () => {
    for (const shape of ['explicit', 'resolved'] as const) {
      const { graph, rules } = callChain(shape);
      const summary = summarizeFunction(graph, HELPER, rules);
      expect(summary.functionId).toBe(HELPER);
      expect(summary.taintedReturnFromParams).toEqual([0]);
      expect(summary.converged).toBe(true);
      expect(summary.findings).toEqual([]);
    }
  });

  it('引数 → シンクの関係を sinkArgIndex 付きで記録する', () => {
    const RUN = 'app.ts::run';
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: RUN, file: FILE, params: [makeParam('cmd', 0)] })],
      nodes: [
        makeNode({ id: `${RUN}#0`, kind: 'param', functionId: RUN, range: at(1), label: 'cmd' }),
        makeNode({ id: `${RUN}#1`, kind: 'call', functionId: RUN, range: at(2), label: 'child_process.exec(cmd)' }),
      ],
      edges: [makeEdge(`${RUN}#0`, `${RUN}#1`, 'argument', 0)],
      sinks: [
        makeSink({
          nodeId: `${RUN}#1`,
          sinkId: 'command-injection',
          functionId: RUN,
          kinds: ['command'],
          range: at(2),
          taintedArgs: [0],
        }),
      ],
    });

    const summary = summarizeFunction(fixture.graph, RUN, fixture.rules);
    expect(summary.paramToSink).toEqual([
      { paramIndex: 0, sinkId: 'command-injection', sinkArgIndex: 0, range: at(2) },
    ]);
    expect(summary.taintedReturnFromParams).toEqual([]);
    expect(summary.findings).toEqual([]);
  });

  it('すべてのタグを落とすサニタイザを通る引数は汚染された戻り値にならない', () => {
    const SANITIZED = 'app.ts::sanitized';
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: SANITIZED, file: FILE, params: [makeParam('x', 0)] })],
      nodes: [
        makeNode({ id: `${SANITIZED}#0`, kind: 'param', functionId: SANITIZED, range: at(1), label: 'x' }),
        makeNode({ id: `${SANITIZED}#1`, kind: 'call', functionId: SANITIZED, range: at(2), label: 'escapeAll(x)' }),
        makeNode({ id: `${SANITIZED}#2`, kind: 'return', functionId: SANITIZED, range: at(3), label: 'x' }),
      ],
      edges: [
        makeEdge(`${SANITIZED}#0`, `${SANITIZED}#1`, 'assign'),
        makeEdge(`${SANITIZED}#1`, `${SANITIZED}#2`, 'return'),
      ],
      sanitizers: [
        makeSanitizer({ nodeId: `${SANITIZED}#1`, sanitizerId: 'escapeAll', kinds: [], functionId: SANITIZED, range: at(2) }),
      ],
    });

    const summary = summarizeFunction(fixture.graph, SANITIZED, fixture.rules);
    expect(summary.taintedReturnFromParams).toEqual([]);
    expect(summary.converged).toBe(true);
  });

  it('findings にはその関数内で確定した検出だけが入る', () => {
    const { graph, rules } = callChain('explicit');
    const handlerSummary = summarizeFunction(graph, HANDLER, rules);
    const helperSummary = summarizeFunction(graph, HELPER, rules);

    expect(handlerSummary.findings).toHaveLength(1);
    expect(handlerSummary.findings[0]?.functionId).toBe(HANDLER);
    expect(helperSummary.findings).toHaveLength(0);
  });

  it('反復上限で打ち切られた関数は converged: false になる', () => {
    const { graph, rules } = callChain('explicit');
    const limited = buildSummaryTable(graph, rules, { maxIterations: 1 });
    const full = buildSummaryTable(graph, rules);

    expect(limited.get(HELPER)?.converged).toBe(false);
    expect(full.get(HELPER)?.converged).toBe(true);
    expect(full.get(HELPER)?.taintedReturnFromParams).toEqual([0]);
  });

  it('buildSummaryTable が全関数分のサマリを決定的な順序で返す', () => {
    const { graph, rules } = callChain('explicit');
    const table = buildSummaryTable(graph, rules);

    expect([...table.keys()]).toEqual([HANDLER, HELPER].sort());
    expect(table.get(HELPER)?.taintedReturnFromParams).toEqual([0]);
    expect(table.get(HANDLER)?.findings).toHaveLength(1);
  });
});
