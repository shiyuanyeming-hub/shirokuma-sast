/**
 * SARIF 2.1.0 レポータのテスト。
 *
 * 検証の柱:
 * - GitHub Code Scanning が読む構造（version / $schema / driver / rules / results）
 * - region の 1-based と、SARIF 特有の「排他的な end」への変換
 * - `driver.rules` の重複排除と `ruleIndex` の整合
 * - `codeFlows` / `partialFingerprints` / `invocations` の中身
 * - 構造検証ヘルパ `validateSarifStructure` が壊れた入力を検出できること
 */

import { describe, expect, it } from 'vitest';
import {
  createSarifReporter,
  validateSarifStructure,
} from '../../src/reporters/sarif.js';
import type { AnalysisResult, Diagnostic, Finding, ProofStep, Severity } from '../../src/types.js';

/** SARIF の region（テストで読む範囲だけを型にする）。 */
interface TestRegion {
  readonly startLine: number;
  readonly startColumn: number;
  readonly endLine: number;
  readonly endColumn: number;
}

/** SARIF の location。 */
interface TestLocation {
  readonly physicalLocation: {
    readonly artifactLocation: { readonly uri: string };
    readonly region?: TestRegion;
  };
  readonly message?: { readonly text: string };
}

/** SARIF の result。 */
interface TestResult {
  readonly ruleId: string;
  readonly ruleIndex: number;
  readonly level: string;
  readonly message: { readonly text: string };
  readonly locations: readonly TestLocation[];
  readonly codeFlows?: readonly {
    readonly threadFlows: readonly {
      readonly locations: readonly {
        readonly location: TestLocation;
        readonly executionOrder: number;
        readonly importance: string;
      }[];
    }[];
  }[];
  readonly partialFingerprints: Readonly<Record<string, string>>;
  readonly properties: Readonly<Record<string, unknown>>;
}

/** SARIF の reportingDescriptor。 */
interface TestRule {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: { readonly text: string };
  readonly fullDescription: { readonly text: string };
  readonly helpUri: string;
  readonly defaultConfiguration: { readonly level: string };
  readonly properties: { readonly tags: readonly string[] };
}

/** SARIF ログ。 */
interface TestLog {
  readonly $schema: string;
  readonly version: string;
  readonly runs: readonly {
    readonly tool: {
      readonly driver: {
        readonly name: string;
        readonly version: string;
        readonly informationUri: string;
        readonly rules: readonly TestRule[];
      };
    };
    readonly columnKind: string;
    readonly invocations: readonly {
      readonly executionSuccessful: boolean;
      readonly toolExecutionNotifications?: readonly {
        readonly level: string;
        readonly message: { readonly text: string };
        readonly locations?: readonly TestLocation[];
      }[];
    }[];
    readonly results: readonly TestResult[];
  }[];
}

/** テスト用の経路。 */
function makeProof(): readonly ProofStep[] {
  return [
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
      range: { start: { line: 10, column: 15 }, end: { line: 10, column: 40 } },
      label: 'sql + id',
      role: 'propagate',
    },
    {
      nodeId: 'n3',
      file: '/repo/src/db.ts',
      range: { start: { line: 11, column: 7 }, end: { line: 11, column: 20 } },
      label: 'escape(id)',
      role: 'sanitize',
      note: 'html',
    },
    {
      nodeId: 'n4',
      file: '/repo/src/db.ts',
      range: { start: { line: 12, column: 5 }, end: { line: 12, column: 20 } },
      label: 'db.query(sql)',
      role: 'sink',
    },
  ];
}

/** 検出 1 件を組み立てる。 */
function makeFinding(overrides: {
  readonly id?: string;
  readonly ruleId?: string;
  readonly severity?: Severity;
  readonly message?: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly relativePath?: string;
  readonly file?: string;
  readonly start?: { readonly line: number; readonly column: number };
  readonly end?: { readonly line: number; readonly column: number };
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
    file: overrides.file ?? '/repo/src/db.ts',
    relativePath: overrides.relativePath ?? 'src/db.ts',
    range: {
      start: overrides.start ?? { line: 12, column: 5 },
      end: overrides.end ?? { line: 12, column: 20 },
    },
    functionId: 'src/db.ts::handler',
    proof: overrides.proof ?? [],
  };
}

/** 解析結果を組み立てる。 */
function makeResult(findings: readonly Finding[], diagnostics: readonly Diagnostic[] = []): AnalysisResult {
  return {
    schemaVersion: 1,
    tool: {
      name: 'shirokuma-sast',
      version: '0.1.0',
      engineVersion: '0.1.0',
      configOrigin: 'builtin',
    },
    files: [],
    findings,
    stats: {
      filesScanned: 3,
      functionsAnalysed: 12,
      flowNodes: 34,
      flowEdges: 40,
      iterations: 7,
      truncated: [],
    },
    diagnostics,
  };
}

/** JSON 文字列を SARIF ログとして読む。 */
function parseLog(sarif: string): TestLog {
  return JSON.parse(sarif) as TestLog;
}

/** 検証テスト用に、任意の JSON 値をオブジェクトとして読む。 */
function record(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('オブジェクトではありません');
  }
  return value as Record<string, unknown>;
}

/** 検証テスト用に、任意の JSON 値を配列として読む。 */
function list(value: unknown): readonly unknown[] {
  if (!Array.isArray(value)) {
    throw new Error('配列ではありません');
  }
  return value;
}

describe('sarif レポータ', () => {
  it('SARIF 2.1.0 の骨格とドライバ情報を持つ', () => {
    const log = parseLog(createSarifReporter().render(makeResult([makeFinding({})])));

    expect(log.version).toBe('2.1.0');
    expect(log.$schema).toContain('sarif');
    expect(log.runs).toHaveLength(1);
    const driver = log.runs[0]?.tool.driver;
    expect(driver?.name).toBe('shirokuma-sast');
    expect(driver?.version).toBe('0.1.0');
    expect(driver?.informationUri).toBe('https://github.com/shirokuma-sast/shirokuma-sast');
    expect(driver?.rules).toHaveLength(1);
  });

  it('informationUri オプションを反映する', () => {
    const log = parseLog(
      createSarifReporter({ informationUri: 'https://example.com/repo' }).render(makeResult([makeFinding({})])),
    );

    expect(log.runs[0]?.tool.driver.informationUri).toBe('https://example.com/repo');
  });

  it('絶対 URI でない informationUri は既定値へフォールバックする', () => {
    const log = parseLog(
      createSarifReporter({ informationUri: './repo' }).render(makeResult([makeFinding({})])),
    );

    expect(log.runs[0]?.tool.driver.informationUri).toBe(
      'https://github.com/shirokuma-sast/shirokuma-sast',
    );
  });

  it('重要度を error / warning / note へ写像する', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([
          makeFinding({ ruleId: 'a', severity: 'error' }),
          makeFinding({ ruleId: 'b', severity: 'warning' }),
          makeFinding({ ruleId: 'c', severity: 'note' }),
        ]),
      ),
    );

    expect(log.runs[0]?.results.map((result) => result.level)).toEqual(['error', 'warning', 'note']);
  });

  it('ruleId を重複排除し、ruleIndex が driver.rules を指す', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([
          makeFinding({ ruleId: 'xss' }),
          makeFinding({ ruleId: 'sql-injection' }),
          makeFinding({ ruleId: 'xss' }),
        ]),
      ),
    );
    const rules = log.runs[0]?.tool.driver.rules ?? [];
    const results = log.runs[0]?.results ?? [];

    expect(rules.map((rule) => rule.id)).toEqual(['sql-injection', 'xss']);
    for (const result of results) {
      expect(rules[result.ruleIndex]?.id).toBe(result.ruleId);
    }
  });

  it('同じ ruleId が複数の重要度で現れたら強い方を採用する', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([
          makeFinding({ ruleId: 'xss', severity: 'note' }),
          makeFinding({ ruleId: 'xss', severity: 'error' }),
        ]),
      ),
    );

    expect(log.runs[0]?.tool.driver.rules[0]?.defaultConfiguration.level).toBe('error');
  });

  it('region を 1-based で出し、end は排他的な終端（+1）へ変換する', () => {
    const log = parseLog(createSarifReporter().render(makeResult([makeFinding({})])));
    const region = log.runs[0]?.results[0]?.locations[0]?.physicalLocation.region;

    expect(region).toEqual({ startLine: 12, startColumn: 5, endLine: 12, endColumn: 21 });
  });

  it('複数行にまたがる範囲も変換できる', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([
          makeFinding({ start: { line: 3, column: 1 }, end: { line: 5, column: 9 } }),
        ]),
      ),
    );
    const region = log.runs[0]?.results[0]?.locations[0]?.physicalLocation.region;

    expect(region).toEqual({ startLine: 3, startColumn: 1, endLine: 5, endColumn: 10 });
  });

  it('1-based でない位置は 1 へ丸め、逆向きの範囲も整合させる', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([
          makeFinding({ start: { line: 0, column: -3 }, end: { line: 0, column: 0 } }),
          makeFinding({ start: { line: 8, column: 10 }, end: { line: 2, column: 1 } }),
        ]),
      ),
    );
    const regions = (log.runs[0]?.results ?? []).map(
      (result) => result.locations[0]?.physicalLocation.region,
    );

    expect(regions[0]).toEqual({ startLine: 1, startColumn: 1, endLine: 1, endColumn: 2 });
    expect(regions[1]).toEqual({ startLine: 8, startColumn: 10, endLine: 8, endColumn: 11 });
  });

  it('汚染経路を codeFlows に入れ、executionOrder を 1 から振る', () => {
    const log = parseLog(createSarifReporter().render(makeResult([makeFinding({ proof: makeProof() })])));
    const locations = log.runs[0]?.results[0]?.codeFlows?.[0]?.threadFlows[0]?.locations ?? [];

    expect(locations).toHaveLength(4);
    expect(locations.map((entry) => entry.executionOrder)).toEqual([1, 2, 3, 4]);
    expect(locations.map((entry) => entry.importance)).toEqual([
      'essential',
      'important',
      'important',
      'essential',
    ]);
    expect(locations[0]?.location.message?.text).toBe('source: req.query.id');
    expect(locations[2]?.location.message?.text).toBe('sanitize: escape(id) (html)');
    expect(locations[3]?.location.physicalLocation.region).toEqual({
      startLine: 12,
      startColumn: 5,
      endLine: 12,
      endColumn: 21,
    });
  });

  it('経路が空なら codeFlows を省略する', () => {
    const log = parseLog(createSarifReporter().render(makeResult([makeFinding({})])));

    expect(log.runs[0]?.results[0]?.codeFlows).toBeUndefined();
  });

  it('経路ステップのパスをルート相対の URI へ短縮する', () => {
    const log = parseLog(createSarifReporter().render(makeResult([makeFinding({ proof: makeProof() })])));
    const locations = log.runs[0]?.results[0]?.codeFlows?.[0]?.threadFlows[0]?.locations ?? [];

    expect(locations.map((entry) => entry.location.physicalLocation.artifactLocation.uri)).toEqual([
      'src/db.ts',
      'src/db.ts',
      'src/db.ts',
      'src/db.ts',
    ]);
  });

  it('artifactLocation.uri をパーセント符号化する', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([makeFinding({ relativePath: 'src/my file#1.ts', file: '/repo/src/my file#1.ts' })]),
      ),
    );

    expect(log.runs[0]?.results[0]?.locations[0]?.physicalLocation.artifactLocation.uri).toBe(
      'src/my%20file%231.ts',
    );
  });

  it('partialFingerprints に安定 ID を入れる', () => {
    const log = parseLog(
      createSarifReporter().render(makeResult([makeFinding({ id: 'sql-injection:src/db.ts:12:5' })])),
    );

    expect(log.runs[0]?.results[0]?.partialFingerprints).toEqual({
      'shirokuma-sast/v1': 'sql-injection:src/db.ts:12:5',
    });
  });

  it('CWE から helpUri とタグを作る', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult([makeFinding({ cwe: ['CWE-89'], advice: 'プレースホルダを使う' })]),
      ),
    );
    const rule = log.runs[0]?.tool.driver.rules[0];

    expect(rule?.helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html');
    expect(rule?.properties.tags).toEqual(['security', 'external/cwe/cwe-089']);
    expect(rule?.shortDescription.text).toContain('SQL');
    expect(rule?.fullDescription.text).toContain('推奨: プレースホルダを使う');
  });

  it('CWE が無いときは informationUri を helpUri にする', () => {
    const log = parseLog(createSarifReporter().render(makeResult([makeFinding({})])));

    expect(log.runs[0]?.tool.driver.rules[0]?.helpUri).toBe(
      'https://github.com/shirokuma-sast/shirokuma-sast',
    );
  });

  it('空のメッセージでも message.text を空にしない', () => {
    const log = parseLog(
      createSarifReporter().render(makeResult([makeFinding({ message: '', ruleId: 'sql-injection' })])),
    );

    expect(log.runs[0]?.results[0]?.message.text).toBe('sql-injection');
  });

  it('診断を invocations の通知として出す', () => {
    const log = parseLog(
      createSarifReporter().render(
        makeResult(
          [makeFinding({})],
          [
            {
              level: 'info',
              message: '3 ファイルを検出',
              file: 'src/broken.ts',
              range: { start: { line: 3, column: 1 }, end: { line: 3, column: 2 } },
            },
            { level: 'error', message: '設定が不正です' },
          ],
        ),
      ),
    );
    const invocation = log.runs[0]?.invocations[0];

    expect(invocation?.executionSuccessful).toBe(true);
    expect(invocation?.toolExecutionNotifications?.map((notification) => notification.level)).toEqual([
      'note',
      'error',
    ]);
    expect(
      invocation?.toolExecutionNotifications?.[0]?.locations?.[0]?.physicalLocation.artifactLocation.uri,
    ).toBe('src/broken.ts');
  });

  it('検出ゼロでも妥当な SARIF を出す', () => {
    const out = createSarifReporter().render(makeResult([]));
    const log = parseLog(out);

    expect(log.runs[0]?.results).toEqual([]);
    expect(validateSarifStructure(out)).toEqual([]);
  });

  it('出力はバイト単位で再現する', () => {
    const result = makeResult([makeFinding({ proof: makeProof(), cwe: ['CWE-89'] })]);
    const reporter = createSarifReporter();

    expect(reporter.render(result)).toBe(reporter.render(result));
    expect(validateSarifStructure(reporter.render(result))).toEqual([]);
  });

  it('生成した SARIF は構造検証を通る', () => {
    const out = createSarifReporter().render(
      makeResult([
        makeFinding({ proof: makeProof(), cwe: ['CWE-89'], advice: 'x' }),
        makeFinding({ ruleId: 'xss', severity: 'note' }),
      ]),
    );

    expect(validateSarifStructure(out)).toEqual([]);
  });

  it('validateSarifStructure は壊れた構造を検出する', () => {
    const problems = validateSarifStructure('{"version":"2.0.0","runs":[]}');

    expect(problems.length).toBeGreaterThan(0);
    expect(problems.some((problem) => problem.includes('version'))).toBe(true);
    expect(problems.some((problem) => problem.includes('$schema'))).toBe(true);
    expect(problems.some((problem) => problem.includes('runs'))).toBe(true);
  });

  it('validateSarifStructure は JSON でない入力を例外ではなく問題として返す', () => {
    const problems = validateSarifStructure('not json');

    expect(problems).toHaveLength(1);
    expect(problems[0]).toContain('JSON');
  });

  it('validateSarifStructure は結果の不整合を検出する', () => {
    const valid = parseLog(createSarifReporter().render(makeResult([makeFinding({ proof: makeProof() })])));
    const mutate = (change: (log: Record<string, unknown>) => void): readonly string[] => {
      const log = record(JSON.parse(JSON.stringify(valid)));
      change(log);
      return validateSarifStructure(JSON.stringify(log));
    };
    /** 最初の result を取り出す（どの変異テストでも使う）。 */
    const firstResult = (log: Record<string, unknown>): Record<string, unknown> =>
      record(list(record(list(log['runs'])[0])['results'])[0]);

    expect(
      mutate((log) => {
        record(record(record(list(log['runs'])[0])['tool'])['driver'])['rules'] = [];
      }),
    ).not.toEqual([]);
    expect(
      mutate((log) => {
        firstResult(log)['level'] = 'fatal';
      }),
    ).not.toEqual([]);
    expect(
      mutate((log) => {
        delete firstResult(log)['partialFingerprints'];
      }),
    ).not.toEqual([]);
    expect(
      mutate((log) => {
        const location = record(list(firstResult(log)['locations'])[0]);
        record(record(location['physicalLocation'])['region'])['startLine'] = 0;
      }),
    ).not.toEqual([]);
    expect(
      mutate((log) => {
        const flow = record(list(firstResult(log)['codeFlows'])[0]);
        record(list(flow['threadFlows'])[0])['locations'] = [];
      }),
    ).not.toEqual([]);
    expect(
      mutate((log) => {
        firstResult(log)['message'] = { text: '' };
      }),
    ).not.toEqual([]);
  });
});
