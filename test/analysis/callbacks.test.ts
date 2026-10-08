/**
 * コールバック配線（高階関数・Express ルートハンドラ）のテスト。
 *
 * `IRGraph` には「呼び出しの引数 → コールバックの仮引数」という意味づけが無いため、
 * `AnalysisHints.callbackLinks` として解析エンジンへ渡す。ここでは
 * `arr.map(x => ...)` / `items.forEach(item => ...)` / `app.get('/x', (req, res) => ...)`
 * の 3 形態と、配線が無い場合・サニタイズ済みの場合の負例を固定する。
 */

import { describe, expect, it } from 'vitest';
import { solveGraph } from '../../src/analysis/solver.js';
import type { AnalysisHints, FlowEdge, FlowNode, FunctionIR } from '../../src/types.js';
import {
  at,
  makeAnalysis,
  makeEdge,
  makeFunction,
  makeNode,
  makeParam,
  makeSanitizer,
  makeSink,
  makeSource,
} from './fixtures.js';

const HANDLER = 'app.ts::handler';
const CALLBACK = 'app.ts::handler$callback';
const FILE = '/proj/app.ts';

/** 「呼び出しノード → コールバック仮引数ノード」の配線を作る。 */
function callbackHints(input: {
  readonly callNodeId: string;
  readonly callbackNodeId: string;
  readonly paramNodeId: string;
  readonly returnNodeId?: string;
}): AnalysisHints {
  return {
    callbackLinks: new Map([
      [
        input.callNodeId,
        [
          {
            callNodeId: input.callNodeId,
            pairs: [{ argNodeId: input.callbackNodeId, paramNodeId: input.paramNodeId }],
            ...(input.returnNodeId !== undefined ? { returnNodeId: input.returnNodeId } : {}),
          },
        ],
      ],
    ]),
    unresolvedCallees: ['map', 'forEach', 'get'],
  };
}

/**
 * `arr.map(x => db.query(x))` の形。
 * `source` は配列（引数）、`sink` はコールバック本体内にある。
 */
function mapCallback(options: { readonly sanitizeInsideCallback?: boolean } = {}) {
  const functions: FunctionIR[] = [
    makeFunction({ id: HANDLER, file: FILE, range: at(1) }),
    makeFunction({ id: CALLBACK, file: FILE, params: [makeParam('x', 0)], range: at(4) }),
  ];
  const nodes: FlowNode[] = [
    makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(3), label: 'req.query.ids' }),
    makeNode({ id: `${HANDLER}#1`, kind: 'call', functionId: HANDLER, range: at(4), label: 'ids.map(x => db.query(x))' }),
    makeNode({ id: `${HANDLER}#2`, kind: 'unknown', functionId: HANDLER, range: at(4), label: 'x => db.query(x)' }),
    makeNode({ id: `${CALLBACK}#0`, kind: 'param', functionId: CALLBACK, range: at(4), label: 'x' }),
    makeNode({ id: `${CALLBACK}#1`, kind: 'call', functionId: CALLBACK, range: at(4), label: 'db.query(x)' }),
  ];
  const edges: FlowEdge[] = [
    makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
    makeEdge(`${CALLBACK}#0`, `${CALLBACK}#1`, 'argument', 0),
  ];
  const sanitize = options.sanitizeInsideCallback ?? false;

  return makeAnalysis({
    functions,
    nodes,
    edges,
    sources: [
      makeSource({ nodeId: `${HANDLER}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: HANDLER, range: at(3) }),
    ],
    sanitizers: sanitize
      ? [
          makeSanitizer({
            nodeId: `${CALLBACK}#0`,
            sanitizerId: 'sqlEscape',
            kinds: ['sql'],
            functionId: CALLBACK,
            range: at(4),
          }),
        ]
      : [],
    sinks: [
      makeSink({
        nodeId: `${CALLBACK}#1`,
        sinkId: 'sql-injection',
        functionId: CALLBACK,
        kinds: ['sql'],
        range: at(4),
        label: 'db.query(x)',
        taintedArgs: [0],
      }),
    ],
    hints: callbackHints({
      callNodeId: `${HANDLER}#1`,
      callbackNodeId: `${HANDLER}#2`,
      paramNodeId: `${CALLBACK}#0`,
    }),
  });
}

/** `items.forEach(item => db.query(item))` の形（配列は引数 0）。 */
function forEachCallback() {
  return makeAnalysis({
    functions: [
      makeFunction({ id: HANDLER, file: FILE, range: at(1) }),
      makeFunction({ id: CALLBACK, file: FILE, params: [makeParam('item', 0)], range: at(6) }),
    ],
    nodes: [
      makeNode({ id: `${HANDLER}#0`, kind: 'local', functionId: HANDLER, range: at(5), label: 'items' }),
      makeNode({ id: `${HANDLER}#1`, kind: 'call', functionId: HANDLER, range: at(6), label: 'items.forEach(item => db.query(item))' }),
      makeNode({ id: `${HANDLER}#2`, kind: 'unknown', functionId: HANDLER, range: at(6), label: 'item => db.query(item)' }),
      makeNode({ id: `${CALLBACK}#0`, kind: 'param', functionId: CALLBACK, range: at(6), label: 'item' }),
      makeNode({ id: `${CALLBACK}#1`, kind: 'call', functionId: CALLBACK, range: at(6), label: 'db.query(item)' }),
    ],
    edges: [
      makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
      makeEdge(`${CALLBACK}#0`, `${CALLBACK}#1`, 'argument', 0),
    ],
    sources: [
      makeSource({ nodeId: `${HANDLER}#0`, sourceId: 'express.body', kinds: ['sql'], functionId: HANDLER, range: at(5) }),
    ],
    sinks: [
      makeSink({
        nodeId: `${CALLBACK}#1`,
        sinkId: 'sql-injection',
        functionId: CALLBACK,
        kinds: ['sql'],
        range: at(6),
        label: 'db.query(item)',
        taintedArgs: [0],
      }),
    ],
    hints: callbackHints({
      callNodeId: `${HANDLER}#1`,
      callbackNodeId: `${HANDLER}#2`,
      paramNodeId: `${CALLBACK}#0`,
    }),
  });
}

describe('コールバック配線: 高階関数', () => {
  it('map のコールバック引数へ汚染を流してシンクを検出する', () => {
    const fixture = mapCallback();
    const outcome = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });

    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.ruleId).toBe('sql-injection');
    expect(outcome.findings[0]?.functionId).toBe(CALLBACK);
    expect(outcome.findings[0]?.relativePath).toBe('app.ts');
    expect(outcome.findings[0]?.proof.map((step) => step.nodeId)).toEqual([
      `${HANDLER}#0`,
      `${HANDLER}#1`,
      `${CALLBACK}#0`,
      `${CALLBACK}#1`,
    ]);
    expect(outcome.findings[0]?.proof.map((step) => step.role)).toEqual([
      'source',
      'propagate',
      'propagate',
      'sink',
    ]);
  });

  it('forEach でも同じようにコールバック引数へ流す', () => {
    const fixture = forEachCallback();
    const withHints = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });
    expect(withHints.findings).toHaveLength(1);
    expect(withHints.findings[0]?.proof[2]?.label).toBe('item');
  });

  it('配線が無ければコールバック引数へは伝播しない（従来どおりの挙動）', () => {
    const fixture = forEachCallback();
    const withoutHints = solveGraph(fixture.graph, fixture.rules);
    const withHints = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });

    expect(withoutHints.findings).toHaveLength(0);
    expect(withHints.findings).toHaveLength(1);
  });

  it('コールバック内でサニタイズされた値はシンクへ届かない（負例）', () => {
    const fixture = mapCallback({ sanitizeInsideCallback: true });
    const outcome = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });
    expect(outcome.findings).toHaveLength(0);
  });

  it('呼び出し前にサニタイズされた値をコールバックへ渡しても検出しない（負例）', () => {
    const fixture = makeAnalysis({
      functions: [
        makeFunction({ id: HANDLER, file: FILE, range: at(1) }),
        makeFunction({ id: CALLBACK, file: FILE, params: [makeParam('x', 0)], range: at(4) }),
      ],
      nodes: [
        makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(3), label: 'req.query.ids' }),
        makeNode({ id: `${HANDLER}#1`, kind: 'call', functionId: HANDLER, range: at(4), label: 'escapeHtml(ids)' }),
        makeNode({ id: `${HANDLER}#2`, kind: 'call', functionId: HANDLER, range: at(5), label: 'ids.map(x => db.query(x))' }),
        makeNode({ id: `${HANDLER}#3`, kind: 'unknown', functionId: HANDLER, range: at(5), label: 'x => db.query(x)' }),
        makeNode({ id: `${CALLBACK}#0`, kind: 'param', functionId: CALLBACK, range: at(5), label: 'x' }),
        makeNode({ id: `${CALLBACK}#1`, kind: 'call', functionId: CALLBACK, range: at(5), label: 'db.query(x)' }),
      ],
      edges: [
        makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'assign'),
        makeEdge(`${HANDLER}#1`, `${HANDLER}#2`, 'argument', 0),
        makeEdge(`${CALLBACK}#0`, `${CALLBACK}#1`, 'argument', 0),
      ],
      sources: [
        makeSource({ nodeId: `${HANDLER}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: HANDLER, range: at(3) }),
      ],
      sanitizers: [
        makeSanitizer({ nodeId: `${HANDLER}#1`, sanitizerId: 'escapeHtml', kinds: [], functionId: HANDLER, range: at(4) }),
      ],
      sinks: [
        makeSink({
          nodeId: `${CALLBACK}#1`,
          sinkId: 'sql-injection',
          functionId: CALLBACK,
          kinds: ['sql'],
          range: at(5),
          taintedArgs: [0],
        }),
      ],
      hints: callbackHints({
        callNodeId: `${HANDLER}#2`,
        callbackNodeId: `${HANDLER}#3`,
        paramNodeId: `${CALLBACK}#0`,
      }),
    });

    expect(solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints }).findings).toHaveLength(0);
  });

  it('コールバックの return 辺による循環があっても停止し、検出は 1 件のまま', () => {
    const fixture = makeAnalysis({
      functions: [
        makeFunction({ id: HANDLER, file: FILE, range: at(1) }),
        makeFunction({ id: CALLBACK, file: FILE, params: [makeParam('x', 0)], range: at(3) }),
      ],
      nodes: [
        makeNode({ id: `${HANDLER}#0`, kind: 'property', functionId: HANDLER, range: at(2), label: 'req.query.ids' }),
        makeNode({ id: `${HANDLER}#1`, kind: 'call', functionId: HANDLER, range: at(3), label: 'ids.map(x => x)' }),
        makeNode({ id: `${HANDLER}#2`, kind: 'call', functionId: HANDLER, range: at(4), label: 'db.query(rows)' }),
        makeNode({ id: `${CALLBACK}#0`, kind: 'param', functionId: CALLBACK, range: at(3), label: 'x' }),
        makeNode({ id: `${CALLBACK}#1`, kind: 'return', functionId: CALLBACK, range: at(3), label: 'x' }),
      ],
      edges: [
        makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
        makeEdge(`${CALLBACK}#0`, `${CALLBACK}#1`, 'assign'),
        // IR 構築が張る戻り値の辺（コールバックの戻り値 → 呼び出しノード）。
        makeEdge(`${CALLBACK}#1`, `${HANDLER}#1`, 'return'),
        makeEdge(`${HANDLER}#1`, `${HANDLER}#2`, 'argument', 0),
      ],
      sources: [
        makeSource({ nodeId: `${HANDLER}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: HANDLER, range: at(2) }),
      ],
      sinks: [
        makeSink({
          nodeId: `${HANDLER}#2`,
          sinkId: 'sql-injection',
          functionId: HANDLER,
          kinds: ['sql'],
          range: at(4),
          taintedArgs: [0],
        }),
      ],
      hints: callbackHints({
        callNodeId: `${HANDLER}#1`,
        callbackNodeId: `${HANDLER}#1`,
        paramNodeId: `${CALLBACK}#0`,
        returnNodeId: `${CALLBACK}#1`,
      }),
    });

    const outcome = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });
    expect(outcome.findings).toHaveLength(1);
    expect(outcome.stats.truncated).toEqual([]);
    expect(outcome.stats.iterations).toBeLessThan(20);
  });

  it('配線が存在しないノードを指す場合は診断を積み、解析は続行する', () => {
    const fixture = forEachCallback();
    const broken: AnalysisHints = callbackHints({
      callNodeId: `${HANDLER}#1`,
      callbackNodeId: `${HANDLER}#2`,
      paramNodeId: `${CALLBACK}#99`,
    });

    const outcome = solveGraph(fixture.graph, fixture.rules, { hints: broken });
    expect(outcome.findings).toHaveLength(0);
    expect(outcome.diagnostics).toHaveLength(1);
    expect(outcome.diagnostics[0]?.level).toBe('warning');
    expect(outcome.diagnostics[0]?.message).toContain(`${CALLBACK}#99`);
  });
});

describe('コールバック配線: Express ルートハンドラ', () => {
  /**
   * `app.get('/users', (req, res) => { ... req.params.id ... })` の形。
   * `req` はコールバックの仮引数であり、そのプロパティがソースになる。
   */
  function expressHandler(options: { readonly sourceInsideCallback: boolean }) {
    const ROUTE = 'app.ts::handler$route';
    return makeAnalysis({
      functions: [
        makeFunction({ id: HANDLER, file: FILE, range: at(1) }),
        makeFunction({
          id: ROUTE,
          file: FILE,
          params: [makeParam('req', 0), makeParam('res', 1)],
          range: at(2),
        }),
      ],
      nodes: [
        makeNode({ id: `${HANDLER}#0`, kind: 'local', functionId: HANDLER, range: at(2), label: "'/users/:id'" }),
        makeNode({ id: `${HANDLER}#1`, kind: 'call', functionId: HANDLER, range: at(2), label: "app.get('/users/:id', handler)" }),
        makeNode({ id: `${HANDLER}#2`, kind: 'unknown', functionId: HANDLER, range: at(2), label: '(req, res) => {...}' }),
        makeNode({ id: `${ROUTE}#0`, kind: 'param', functionId: ROUTE, range: at(2), label: 'req' }),
        makeNode({ id: `${ROUTE}#1`, kind: 'property', functionId: ROUTE, range: at(3), label: 'req.params.id' }),
        makeNode({ id: `${ROUTE}#2`, kind: 'call', functionId: ROUTE, range: at(4), label: 'db.query(sql)' }),
      ],
      edges: [
        makeEdge(`${HANDLER}#0`, `${HANDLER}#1`, 'argument', 0),
        makeEdge(`${ROUTE}#0`, `${ROUTE}#2`, 'argument', 0),
        makeEdge(`${ROUTE}#1`, `${ROUTE}#2`, 'argument', 0),
      ],
      sources: options.sourceInsideCallback
        ? [
            makeSource({
              nodeId: `${ROUTE}#1`,
              sourceId: 'express.params',
              kinds: ['sql'],
              functionId: ROUTE,
              range: at(3),
              label: 'req.params.id',
            }),
          ]
        : [
            makeSource({
              nodeId: `${HANDLER}#0`,
              sourceId: 'express.query',
              kinds: ['sql'],
              functionId: HANDLER,
              range: at(2),
            }),
          ],
      sinks: [
        makeSink({
          nodeId: `${ROUTE}#2`,
          sinkId: 'sql-injection',
          functionId: ROUTE,
          kinds: ['sql'],
          range: at(4),
          label: 'db.query(sql)',
          taintedArgs: [0],
        }),
      ],
      hints: callbackHints({
        callNodeId: `${HANDLER}#1`,
        callbackNodeId: `${HANDLER}#2`,
        paramNodeId: `${ROUTE}#0`,
      }),
    });
  }

  it('ルートハンドラ内のソース（req.params）からシンクまで検出する', () => {
    const fixture = expressHandler({ sourceInsideCallback: true });
    const outcome = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });

    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.functionId).toBe('app.ts::handler$route');
    expect(outcome.findings[0]?.proof.map((step) => step.nodeId)).toEqual([
      'app.ts::handler$route#1',
      'app.ts::handler$route#2',
    ]);
  });

  it('呼び出し側の汚染がハンドラの仮引数（req）へ流れてシンクに届く', () => {
    const fixture = expressHandler({ sourceInsideCallback: false });
    const outcome = solveGraph(fixture.graph, fixture.rules, { hints: fixture.hints });

    expect(outcome.findings).toHaveLength(1);
    expect(outcome.findings[0]?.proof.map((step) => step.nodeId)).toEqual([
      `${HANDLER}#0`,
      `${HANDLER}#1`,
      'app.ts::handler$route#0',
      'app.ts::handler$route#2',
    ]);
    expect(outcome.findings[0]?.proof.map((step) => step.role)).toEqual([
      'source',
      'propagate',
      'propagate',
      'sink',
    ]);
  });
});
