/**
 * JSON レポータのテスト。
 *
 * 検証の柱:
 * - 2 スペースインデント・末尾改行・キー順の固定（差分が安定する）
 * - 省略可能なフィールドはキーごと出さない（欠落と空値を区別する）
 * - 値が等しければ別オブジェクトでもバイト単位で同一になること
 */

import { describe, expect, it } from 'vitest';
import { createJsonReporter } from '../../src/reporters/json.js';
import type { AnalysisResult, Finding, ProofStep, Severity } from '../../src/types.js';

/** 検出 1 件を組み立てる。 */
function makeFinding(overrides: {
  readonly id?: string;
  readonly ruleId?: string;
  readonly severity?: Severity;
  readonly message?: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly proof?: readonly ProofStep[];
}): Finding {
  return {
    id: overrides.id ?? 'sql-injection:src/db.ts:12:5',
    ruleId: overrides.ruleId ?? 'sql-injection',
    severity: overrides.severity ?? 'error',
    message: overrides.message ?? 'SQL 文字列の連結に外部入力が混入しています',
    ...(overrides.advice === undefined ? {} : { advice: overrides.advice }),
    ...(overrides.cwe === undefined ? {} : { cwe: overrides.cwe }),
    kinds: ['sql'],
    sourceId: 'express-query',
    sinkId: 'sql-injection',
    file: '/repo/src/db.ts',
    relativePath: 'src/db.ts',
    range: { start: { line: 12, column: 5 }, end: { line: 12, column: 20 } },
    functionId: 'src/db.ts::handler',
    proof: overrides.proof ?? [],
  };
}

/** 解析結果を組み立てる。 */
function makeResult(findings: readonly Finding[]): AnalysisResult {
  return {
    schemaVersion: 1,
    tool: {
      name: 'shirokuma-sast',
      version: '0.1.0',
      engineVersion: '0.1.0',
      configOrigin: 'builtin',
    },
    files: [{ path: '/repo/src/db.ts', relativePath: 'src/db.ts', hash: '0123456789abcdef', lineCount: 42 }],
    findings,
    stats: {
      filesScanned: 3,
      functionsAnalysed: 12,
      flowNodes: 34,
      flowEdges: 40,
      iterations: 7,
      truncated: ['src/a.ts::deep'],
    },
    diagnostics: [
      {
        level: 'warning',
        message: '解析できませんでした',
        file: 'src/broken.ts',
        range: { start: { line: 3, column: 1 }, end: { line: 3, column: 2 } },
      },
    ],
  };
}

/** JSON 文字列をオブジェクトとして読む（テスト用の最小ヘルパ）。 */
function parse(json: string): Record<string, unknown> {
  const value: unknown = JSON.parse(json);
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('JSON オブジェクトではありません');
  }
  return value as Record<string, unknown>;
}

describe('json レポータ', () => {
  it('2 スペースインデントで出力し、末尾に改行を 1 つだけ付ける', () => {
    const out = createJsonReporter().render(makeResult([makeFinding({})]));

    expect(out.endsWith('}\n')).toBe(true);
    expect(out.endsWith('\n\n')).toBe(false);
    expect(out).toContain('\n  "schemaVersion": 1,');
    expect(out).toBe(`${JSON.stringify(JSON.parse(out), null, 2)}\n`);
  });

  it('format は json を返す', () => {
    expect(createJsonReporter().format).toBe('json');
  });

  it('トップレベルと主要オブジェクトのキー順を固定する', () => {
    const document = parse(createJsonReporter().render(makeResult([makeFinding({ advice: 'a', cwe: ['CWE-89'] })])));

    expect(Object.keys(document)).toEqual([
      'schemaVersion',
      'tool',
      'stats',
      'findings',
      'diagnostics',
      'files',
    ]);
    expect(Object.keys(document['tool'] as object)).toEqual([
      'name',
      'version',
      'engineVersion',
      'configOrigin',
    ]);
    expect(Object.keys(document['stats'] as object)).toEqual([
      'filesScanned',
      'functionsAnalysed',
      'flowNodes',
      'flowEdges',
      'iterations',
      'truncated',
    ]);
    const findings = document['findings'] as readonly Record<string, unknown>[];
    expect(Object.keys(findings[0] as object)).toEqual([
      'id',
      'ruleId',
      'severity',
      'message',
      'advice',
      'cwe',
      'kinds',
      'sourceId',
      'sinkId',
      'file',
      'relativePath',
      'range',
      'functionId',
      'proof',
    ]);
    expect(Object.keys((findings[0] as Record<string, unknown>)['range'] as object)).toEqual(['start', 'end']);
    const files = document['files'] as readonly Record<string, unknown>[];
    expect(Object.keys(files[0] as object)).toEqual(['path', 'relativePath', 'hash', 'lineCount']);
  });

  it('省略可能なフィールドはキー自体を出さない', () => {
    const document = parse(createJsonReporter().render(makeResult([makeFinding({})])));
    const finding = (document['findings'] as readonly Record<string, unknown>[])[0] as Record<string, unknown>;

    expect('advice' in finding).toBe(false);
    expect('cwe' in finding).toBe(false);
    const diagnostics = document['diagnostics'] as readonly Record<string, unknown>[];
    expect(Object.keys(diagnostics[0] as object)).toEqual(['level', 'message', 'file', 'range']);
  });

  it('経路ステップの note も値があるときだけ出す', () => {
    const proof: readonly ProofStep[] = [
      {
        nodeId: 'n1',
        file: '/repo/src/db.ts',
        range: { start: { line: 9, column: 11 }, end: { line: 9, column: 22 } },
        label: 'req.query.id',
        role: 'source',
      },
      {
        nodeId: 'n2',
        file: '/repo/src/db.ts',
        range: { start: { line: 11, column: 7 }, end: { line: 11, column: 20 } },
        label: 'escape(id)',
        role: 'sanitize',
        note: 'html',
      },
    ];
    const document = parse(createJsonReporter().render(makeResult([makeFinding({ proof })])));
    const finding = (document['findings'] as readonly Record<string, unknown>[])[0] as Record<string, unknown>;
    const steps = finding['proof'] as readonly Record<string, unknown>[];

    expect(Object.keys(steps[0] as object)).toEqual(['nodeId', 'role', 'file', 'range', 'label']);
    expect(Object.keys(steps[1] as object)).toEqual(['nodeId', 'role', 'file', 'range', 'label', 'note']);
    expect((steps[1] as Record<string, unknown>)['note']).toBe('html');
  });

  it('検出の並び順を入力のまま保持する', () => {
    const document = parse(
      createJsonReporter().render(
        makeResult([
          makeFinding({ id: 'b:src/b.ts:2:2', ruleId: 'b' }),
          makeFinding({ id: 'a:src/a.ts:1:1', ruleId: 'a' }),
        ]),
      ),
    );
    const findings = document['findings'] as readonly Record<string, unknown>[];

    expect(findings.map((finding) => finding['ruleId'])).toEqual(['b', 'a']);
  });

  it('位置情報を 1-based のまま保持する', () => {
    const document = parse(createJsonReporter().render(makeResult([makeFinding({})])));
    const finding = (document['findings'] as readonly Record<string, unknown>[])[0] as Record<string, unknown>;
    const range = finding['range'] as { start: { line: number; column: number }; end: { line: number; column: number } };

    expect(range.start).toEqual({ line: 12, column: 5 });
    expect(range.end).toEqual({ line: 12, column: 20 });
  });

  it('統計・診断・ファイル情報を含める', () => {
    const document = parse(createJsonReporter().render(makeResult([makeFinding({})])));
    const stats = document['stats'] as Record<string, unknown>;
    const files = document['files'] as readonly Record<string, unknown>[];

    expect(stats['truncated']).toEqual(['src/a.ts::deep']);
    expect(document['diagnostics']).toHaveLength(1);
    expect(files[0]).toEqual({
      path: '/repo/src/db.ts',
      relativePath: 'src/db.ts',
      hash: '0123456789abcdef',
      lineCount: 42,
    });
  });

  it('等価な別オブジェクトからもバイト単位で同一の出力になる', () => {
    const first = makeResult([makeFinding({ advice: 'x' }), makeFinding({ ruleId: 'xss', severity: 'note' })]);
    const second = makeResult([makeFinding({ advice: 'x' }), makeFinding({ ruleId: 'xss', severity: 'note' })]);
    const reporter = createJsonReporter();

    expect(reporter.render(first)).toBe(reporter.render(second));
    expect(reporter.render(first)).toBe(reporter.render(first));
  });

  it('検出がゼロでも妥当な JSON を返す', () => {
    const document = parse(createJsonReporter().render(makeResult([])));

    expect(document['findings']).toEqual([]);
    expect(document['schemaVersion']).toBe(1);
  });
});
