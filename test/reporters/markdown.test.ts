/**
 * Markdown レポータのテスト。
 *
 * 検証の柱:
 * - 一覧テーブルと詳細セクションの形
 * - 信頼できないテキスト（`|`、バッククォート、改行、生 HTML）で表やコードスパンが壊れないこと
 * - `maxFindings` による切り詰めと注記
 * - 同一入力に対するバイト単位の再現性
 */

import { describe, expect, it } from 'vitest';
import { createMarkdownReporter } from '../../src/reporters/markdown.js';
import type { AnalysisResult, Diagnostic, Finding, ProofStep } from '../../src/types.js';

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
  readonly severity?: Finding['severity'];
  readonly message?: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly kinds?: readonly string[];
  readonly relativePath?: string;
  readonly functionId?: string;
  readonly proof?: readonly ProofStep[];
}): Finding {
  return {
    id: overrides.id ?? 'sql-injection:src/db.ts:12:5',
    ruleId: overrides.ruleId ?? 'sql-injection',
    severity: overrides.severity ?? 'error',
    message: overrides.message ?? 'SQL 文字列の連結に外部入力が混入しています',
    ...(overrides.advice === undefined ? {} : { advice: overrides.advice }),
    ...(overrides.cwe === undefined ? {} : { cwe: overrides.cwe }),
    kinds: overrides.kinds ?? ['sql'],
    sourceId: 'express-query',
    sinkId: 'sql-injection',
    file: '/repo/src/db.ts',
    relativePath: overrides.relativePath ?? 'src/db.ts',
    range: { start: { line: 12, column: 5 }, end: { line: 12, column: 20 } },
    functionId: overrides.functionId ?? 'src/db.ts::handler',
    proof: overrides.proof ?? [],
  };
}

/** 解析結果を組み立てる。 */
function makeResult(
  findings: readonly Finding[],
  diagnostics: readonly Diagnostic[] = [],
): AnalysisResult {
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

/** エスケープされていない `|` の数（テーブルのセル区切りだけを数える）。 */
function unescapedPipes(line: string): number {
  return line.split(/(?<!\\)\|/u).length - 1;
}

/** エスケープされていないバッククォートの数。 */
function unescapedBackticks(line: string): number {
  return line.split(/(?<!\\)`/u).length - 1;
}

describe('markdown レポータ', () => {
  it('見出し・メタ情報・一覧テーブル・詳細を出す', () => {
    const out = createMarkdownReporter().render(
      makeResult([makeFinding({ proof: makeProof(), advice: 'プレースホルダを使う', cwe: ['CWE-89'] })]),
    );

    expect(out.startsWith('# shirokuma-sast レポート\n')).toBe(true);
    expect(out).toContain('- 検出: **1 件**（error 1 / warning 0 / note 0）');
    expect(out).toContain('## 検出一覧');
    expect(out).toContain('| # | 重要度 | ルール | 位置 | メッセージ |');
    expect(out).toContain('## 検出の詳細');
    expect(out).toContain('- CWE: [CWE-89](https://cwe.mitre.org/data/definitions/89.html)');
    expect(out).toContain('- 推奨: プレースホルダを使う');
    expect(out).toContain('1. `source` — `src/db.ts:9:11` — `req.query.id`');
    expect(out.endsWith('\n')).toBe(true);
    expect(out.endsWith('\n\n')).toBe(false);
  });

  it('ルール ID・位置・メッセージをテーブルに載せる', () => {
    const out = createMarkdownReporter().render(makeResult([makeFinding({})]));
    const row = out.split('\n').find((line) => line.startsWith('| 1 |'));

    expect(row).toBe('| 1 | error | sql-injection | src/db.ts:12:5 | SQL 文字列の連結に外部入力が混入しています |');
  });

  it('メッセージ中の `|` がテーブルを壊さない', () => {
    const out = createMarkdownReporter().render(
      makeResult([
        makeFinding({ message: 'a | b || c' }),
        makeFinding({ id: 'x:src/a.ts:1:1', ruleId: 'x | y', severity: 'note' }),
      ]),
    );
    const rows = out.split('\n').filter((line) => line.startsWith('| '));

    for (const row of rows) {
      expect(unescapedPipes(row)).toBe(6);
    }
    expect(out).toContain('a \\| b \\|\\| c');
  });

  it('メッセージ中の改行を 1 行へ畳む', () => {
    const out = createMarkdownReporter().render(
      makeResult([makeFinding({ message: '前半\n後半\r\n\t末尾' })]),
    );
    const row = out.split('\n').find((line) => line.startsWith('| 1 |'));

    expect(row).toBe('| 1 | error | sql-injection | src/db.ts:12:5 | 前半 後半 末尾 |');
  });

  it('生 HTML をエスケープする', () => {
    const out = createMarkdownReporter().render(
      makeResult([makeFinding({ message: '<script>alert("x")</script>' })]),
    );

    expect(out).toContain('&lt;script&gt;alert("x")&lt;/script&gt;');
    expect(out).not.toContain('<script>');
  });

  it('バッククォートを含むラベルでもコードスパンを壊さない', () => {
    const proof: readonly ProofStep[] = [
      {
        nodeId: 'n1',
        file: '/repo/src/db.ts',
        range: { start: { line: 9, column: 1 }, end: { line: 9, column: 2 } },
        label: 'a`b',
        role: 'source',
      },
      {
        nodeId: 'n2',
        file: '/repo/src/db.ts',
        range: { start: { line: 10, column: 1 }, end: { line: 10, column: 2 } },
        label: '`leading',
        role: 'sink',
      },
    ];
    const out = createMarkdownReporter().render(makeResult([makeFinding({ proof })]));

    expect(out).toContain('``a`b``');
    expect(out).toContain('`` `leading ``');
    for (const row of out.split('\n').filter((line) => line.startsWith('| '))) {
      expect(unescapedBackticks(row)).toBe(0);
    }
  });

  it('CWE が無い場合はリンクを出さない', () => {
    const out = createMarkdownReporter().render(makeResult([makeFinding({})]));

    expect(out).not.toContain('cwe.mitre.org');
    expect(out).not.toContain('- CWE:');
  });

  it('maxFindings で一覧と詳細を切り詰め、注記を出す', () => {
    const findings = [1, 2, 3, 4, 5].map((index) =>
      makeFinding({
        id: `rule-${index}:src/a.ts:${index}:1`,
        ruleId: `rule-${index}`,
        relativePath: `src/a${index}.ts`,
      }),
    );
    const out = createMarkdownReporter({ maxFindings: 2 }).render(makeResult(findings));

    expect(out).toContain('残り 3 件の検出は省略しました');
    expect(out).toContain('### 2. error — rule-2');
    expect(out).not.toContain('### 3. error — rule-3');
    expect(out.split('\n').filter((line) => line.startsWith('| ') && !line.includes('---'))).toHaveLength(3);
  });

  it('検出がゼロのときは検出なしと出す', () => {
    const out = createMarkdownReporter().render(makeResult([]));

    expect(out).toContain('**検出なし**');
    expect(out).not.toContain('## 検出一覧');
  });

  it('診断と打ち切り関数を載せる', () => {
    const result: AnalysisResult = {
      ...makeResult(
        [makeFinding({})],
        [
          {
            level: 'warning',
            message: '解析できませんでした',
            file: 'src/broken.ts',
            range: { start: { line: 3, column: 1 }, end: { line: 3, column: 2 } },
          },
        ],
      ),
      stats: {
        filesScanned: 3,
        functionsAnalysed: 12,
        flowNodes: 34,
        flowEdges: 40,
        iterations: 7,
        truncated: ['src/a.ts::deep'],
      },
    };
    const out = createMarkdownReporter().render(result);

    expect(out).toContain('## 診断');
    expect(out).toContain('| warning | src/broken.ts:3:1 | 解析できませんでした |');
    expect(out).toContain('解析を打ち切った関数: `src/a.ts::deep`');
  });

  it('等価な別オブジェクトからもバイト単位で同一の出力になる', () => {
    const first = makeResult([makeFinding({ proof: makeProof() })]);
    const second = makeResult([makeFinding({ proof: makeProof() })]);
    const reporter = createMarkdownReporter();

    expect(reporter.render(first)).toBe(reporter.render(second));
    expect(reporter.render(first)).toBe(reporter.render(first));
  });
});
