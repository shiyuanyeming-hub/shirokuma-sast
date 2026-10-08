/**
 * サニタイザの意味論テスト。
 * 「有効なサニタイザは自分のタグだけを落とす」「無効なサニタイザは汚染を止めない」
 * という契約の中核を、正例と負例の両方で固定する。
 */

import { describe, expect, it } from 'vitest';
import { analyze } from '../../src/analysis/solver.js';
import type { FlowKind, FlowNode } from '../../src/types.js';
import {
  at,
  makeAnalysis,
  makeEdge,
  makeFunction,
  makeNode,
  makeSanitizer,
  makeSink,
  makeSource,
} from './fixtures.js';

const FN = 'app.ts::handler';
const FILE = '/proj/app.ts';

/** `app.ts::handler` に属するノードを作る。 */
function node(index: number, kind: FlowKind, label: string, line: number): FlowNode {
  return makeNode({ id: `${FN}#${index}`, kind, functionId: FN, range: at(line), label });
}

/**
 * `s0(source) → san(sanitizer) → sink` の 3 ノードグラフを組む。
 * サニタイザの `valid` と `kinds`、ソースとシンクのタグだけを差し替えて使う。
 */
function sanitizerChain(options: {
  readonly sourceKinds?: readonly string[];
  readonly sanitizerKinds?: readonly string[];
  readonly valid?: boolean;
  readonly invalidReason?: string;
  readonly sinkKinds?: readonly string[];
}) {
  const sourceKinds = options.sourceKinds ?? ['sql'];
  return makeAnalysis({
    functions: [makeFunction({ id: FN, file: FILE })],
    nodes: [
      node(0, 'property', 'req.query.id', 3),
      node(1, 'call', 'db.query(sql, [id])', 4),
      node(2, 'call', 'db.raw(sql)', 5),
    ],
    edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'assign'), makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0)],
    sources: [
      makeSource({
        nodeId: `${FN}#0`,
        sourceId: 'express.query',
        kinds: sourceKinds,
        functionId: FN,
        range: at(3),
      }),
    ],
    sanitizers: [
      makeSanitizer({
        nodeId: `${FN}#1`,
        sanitizerId: 'db.query',
        kinds: options.sanitizerKinds ?? ['sql'],
        ...(options.valid !== undefined ? { valid: options.valid } : {}),
        ...(options.invalidReason !== undefined ? { invalidReason: options.invalidReason } : {}),
        functionId: FN,
        range: at(4),
      }),
    ],
    sinks: [
      makeSink({
        nodeId: `${FN}#2`,
        sinkId: 'sql-injection',
        functionId: FN,
        kinds: options.sinkKinds ?? ['sql'],
        range: at(5),
        label: 'db.raw(sql)',
        taintedArgs: [0],
      }),
    ],
  });
}

describe('サニタイザ: 有効な無害化', () => {
  it('有効なサニタイザでタグが尽きたトークンは伝播を停止する', () => {
    const { graph, rules } = sanitizerChain({ valid: true });
    expect(analyze(graph, rules).findings).toHaveLength(0);
  });

  it('サニタイザの kinds が空なら「すべてのタグ」を落とす', () => {
    const { graph, rules } = sanitizerChain({ sourceKinds: ['sql', 'html'], sanitizerKinds: [] });
    expect(analyze(graph, rules).findings).toHaveLength(0);
  });

  it('自分のタグだけを落とし、残ったタグでは検出を続ける', () => {
    const { graph, rules } = sanitizerChain({
      sourceKinds: ['html', 'sql'],
      sanitizerKinds: ['html'],
      sinkKinds: ['sql'],
    });

    const findings = analyze(graph, rules).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]?.kinds).toEqual(['sql']);
  });

  it('無害化されないタグのシンクへは届かない', () => {
    const { graph, rules } = sanitizerChain({
      sourceKinds: ['sql', 'html'],
      sanitizerKinds: ['html'],
      sinkKinds: ['html'],
    });
    expect(analyze(graph, rules).findings).toHaveLength(0);
  });

  it('proof に sanitize ステップとサニタイザ名・落としたタグの注記が入る', () => {
    const { graph, rules } = sanitizerChain({
      sourceKinds: ['html', 'sql'],
      sanitizerKinds: ['html'],
      sinkKinds: ['sql'],
    });

    const finding = analyze(graph, rules).findings[0];
    expect(finding?.proof.map((step) => step.role)).toEqual(['source', 'sanitize', 'sink']);
    expect(finding?.proof[1]?.nodeId).toBe(`${FN}#1`);
    expect(finding?.proof[1]?.note).toBe('サニタイザ db.query により html を無害化');
  });

  it('無関係なタグだけを対象にしたサニタイザは sanitize ステップを作らない', () => {
    const { graph, rules } = sanitizerChain({
      sourceKinds: ['sql'],
      sanitizerKinds: ['html'],
      sinkKinds: ['sql'],
    });

    const finding = analyze(graph, rules).findings[0];
    expect(finding?.proof.map((step) => step.role)).toEqual(['source', 'propagate', 'sink']);
    expect(finding?.proof[1]?.note).toBeUndefined();
  });
});

describe('サニタイザ: 無効な用法', () => {
  it('valid: false のサニタイザは汚染を止めない', () => {
    const { graph, rules } = sanitizerChain({
      valid: false,
      invalidReason: '第 1 引数が文字列リテラルではありません',
    });

    const findings = analyze(graph, rules).findings;
    expect(findings).toHaveLength(1);
    expect(findings[0]?.proof.map((step) => step.role)).toEqual(['source', 'propagate', 'sink']);
  });

  it('valid を省略した場合も無害化しない（既定は契約どおり出現側の値を尊重）', () => {
    const { graph, rules } = sanitizerChain({ valid: false });
    expect(analyze(graph, rules).findings).toHaveLength(1);
  });
});

describe('サニタイザ: 経路の組み合わせ', () => {
  it('サニタイズされた経路と無害化されない経路が併存する場合は検出する', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [
        node(0, 'property', 'req.query.id', 3),
        node(1, 'call', 'db.query(sql, [id])', 4),
        node(2, 'call', 'db.raw(sql)', 5),
      ],
      // 経路 A: #0 → #1（サニタイザ）→ #2、経路 B: #0 → #2（直接）
      edges: [
        makeEdge(`${FN}#0`, `${FN}#1`, 'assign'),
        makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0),
        makeEdge(`${FN}#0`, `${FN}#2`, 'argument', 0),
      ],
      sources: [makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN })],
      sanitizers: [
        makeSanitizer({ nodeId: `${FN}#1`, sanitizerId: 'db.query', kinds: ['sql'], functionId: FN, range: at(4) }),
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

    const findings = analyze(fixture.graph, fixture.rules).findings;
    expect(findings).toHaveLength(1);
    // 生き残ったのは無害化されていない経路（サニタイザを経由しない）。
    expect(findings[0]?.proof.map((step) => step.nodeId)).toEqual([`${FN}#0`, `${FN}#2`]);
  });

  it('ソースノード自身がサニタイザなら、その時点でタグが落ちる', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'call', 'db.query(req.query.id)', 3), node(1, 'call', 'db.raw(sql)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'argument', 0)],
      sources: [makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql'], functionId: FN })],
      sanitizers: [
        makeSanitizer({ nodeId: `${FN}#0`, sanitizerId: 'db.query', kinds: ['sql'], functionId: FN, range: at(3) }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#1`,
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

  it('同一ノードの複数サニタイザを順に適用する', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(1, 'call', 'sanitizeAll(id)', 4), node(2, 'call', 'db.raw(sql)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'assign'), makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0)],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql', 'html'], functionId: FN }),
      ],
      sanitizers: [
        makeSanitizer({ nodeId: `${FN}#1`, sanitizerId: 'escapeHtml', kinds: ['html'], functionId: FN, range: at(4) }),
        makeSanitizer({ nodeId: `${FN}#1`, sanitizerId: 'sqlEscape', kinds: ['sql'], functionId: FN, range: at(4) }),
      ],
      sinks: [
        makeSink({
          nodeId: `${FN}#2`,
          sinkId: 'sql-injection',
          functionId: FN,
          kinds: ['sql', 'html'],
          range: at(5),
          taintedArgs: [0],
        }),
      ],
    });

    // タグが尽きるため伝播は止まる。
    expect(analyze(fixture.graph, fixture.rules).findings).toHaveLength(0);
  });

  it('複数サニタイザのうち片方だけが落とした場合は残タグで検出し、両方を注記する', () => {
    const fixture = makeAnalysis({
      functions: [makeFunction({ id: FN, file: FILE })],
      nodes: [node(0, 'property', 'req.query.id', 3), node(1, 'call', 'sanitizeSome(id)', 4), node(2, 'call', 'db.raw(sql)', 5)],
      edges: [makeEdge(`${FN}#0`, `${FN}#1`, 'assign'), makeEdge(`${FN}#1`, `${FN}#2`, 'argument', 0)],
      sources: [
        makeSource({ nodeId: `${FN}#0`, sourceId: 'express.query', kinds: ['sql', 'html', 'path'], functionId: FN }),
      ],
      sanitizers: [
        makeSanitizer({ nodeId: `${FN}#1`, sanitizerId: 'escapeHtml', kinds: ['html'], functionId: FN, range: at(4) }),
        makeSanitizer({ nodeId: `${FN}#1`, sanitizerId: 'pathGuard', kinds: ['path'], functionId: FN, range: at(4) }),
        makeSanitizer({ nodeId: `${FN}#1`, sanitizerId: 'noop', kinds: ['nosql'], functionId: FN, range: at(4) }),
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

    const finding = analyze(fixture.graph, fixture.rules).findings[0];
    expect(finding?.kinds).toEqual(['sql']);
    expect(finding?.proof[1]?.role).toBe('sanitize');
    expect(finding?.proof[1]?.note).toBe('サニタイザ escapeHtml, pathGuard により html, path を無害化');
  });
});
