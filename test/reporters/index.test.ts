/**
 * レポータのエントリポイント（`createReporter`）と構造検証ヘルパのテスト。
 *
 * `contract.ts` は `declare function` だけの型専用モジュールなので、
 * 実行時の値はこの `index.ts` からしか取れない。その導線が壊れていないことを固定する。
 */

import { describe, expect, it } from 'vitest';
import {
  createJsonReporter,
  createMarkdownReporter,
  createPrettyReporter,
  createReporter,
  createSarifReporter,
  DEFAULT_INFORMATION_URI,
  validateSarifStructure,
} from '../../src/reporters/index.js';
import type { ReporterFormat } from '../../src/reporters/index.js';
import type { AnalysisResult, Finding } from '../../src/types.js';

/** 検出 1 件を組み立てる。 */
function makeFinding(): Finding {
  return {
    id: 'sql-injection:src/db.ts:12:5',
    ruleId: 'sql-injection',
    severity: 'error',
    message: 'SQL 文字列の連結に外部入力が混入しています',
    kinds: ['sql'],
    sourceId: 'express-query',
    sinkId: 'sql-injection',
    file: '/repo/src/db.ts',
    relativePath: 'src/db.ts',
    range: { start: { line: 12, column: 5 }, end: { line: 12, column: 20 } },
    functionId: 'src/db.ts::handler',
    proof: [],
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
    files: [],
    findings,
    stats: {
      filesScanned: 1,
      functionsAnalysed: 1,
      flowNodes: 1,
      flowEdges: 0,
      iterations: 1,
      truncated: [],
    },
    diagnostics: [],
  };
}

describe('reporters エントリポイント', () => {
  it('format から 4 種類のレポータを引ける', () => {
    const formats: readonly ReporterFormat[] = ['pretty', 'json', 'sarif', 'markdown'];

    expect(formats.map((format) => createReporter(format).format)).toEqual([
      'pretty',
      'json',
      'sarif',
      'markdown',
    ]);
  });

  it('pretty の color オプションを渡せる', () => {
    const result = makeResult([makeFinding()]);

    expect(createReporter('pretty').render(result)).not.toContain('\u001b');
    expect(createReporter('pretty', { color: true }).render(result)).toContain('\u001b[');
  });

  it('sarif の informationUri オプションを渡せる', () => {
    const out = createReporter('sarif', { informationUri: 'https://example.com/repo' }).render(
      makeResult([makeFinding()]),
    );

    expect(out).toContain('"informationUri": "https://example.com/repo"');
    expect(DEFAULT_INFORMATION_URI).toBe('https://github.com/shirokuma-sast/shirokuma-sast');
  });

  it('未知の形式は例外を投げる', () => {
    const unknown = 'yaml' as ReporterFormat;

    expect(() => createReporter(unknown)).toThrow(/未知の出力形式/u);
  });

  it('各ファクトリが対応する format を返す', () => {
    expect(createPrettyReporter().format).toBe('pretty');
    expect(createJsonReporter().format).toBe('json');
    expect(createSarifReporter().format).toBe('sarif');
    expect(createMarkdownReporter().format).toBe('markdown');
  });

  it('validateSarifStructure を再輸出している', () => {
    const out = createReporter('sarif').render(makeResult([makeFinding()]));

    expect(validateSarifStructure(out)).toEqual([]);
  });

  it('createReporter 経由の出力もバイト単位で再現する', () => {
    const result = makeResult([makeFinding()]);

    for (const format of ['pretty', 'json', 'sarif', 'markdown'] as const) {
      const reporter = createReporter(format);
      expect(reporter.render(result)).toBe(reporter.render(result));
    }
  });
});
