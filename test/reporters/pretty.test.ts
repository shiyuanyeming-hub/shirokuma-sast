/**
 * Pretty レポータのテスト。
 *
 * 検証の柱:
 * - 端末出力の形（見出し・検出ブロック・経路ツリー・サマリ）
 * - `color` の有無が構造を変えないこと（ANSI を除去すると色なし出力と一致）
 * - 制御文字（とくに ESC）を無害化すること — 検出ラベルはソース由来＝信頼できない入力
 * - 経路の表示上限と、source / sink を残す省略の挙動
 * - 同一入力に対するバイト単位の再現性
 */

import { describe, expect, it } from 'vitest';
import { createPrettyReporter } from '../../src/reporters/pretty.js';
import type {
  AnalysisResult,
  Diagnostic,
  Finding,
  ProofStep,
  Severity,
  SourceFileInfo,
} from '../../src/types.js';

/** テスト用の経路（source → propagate → sanitize → sink の 4 ステップ）。 */
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

/** 検出 1 件を組み立てる（省略可能なフィールドは値があるときだけ入る）。 */
function makeFinding(overrides: {
  readonly id?: string;
  readonly ruleId?: string;
  readonly severity?: Severity;
  readonly message?: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly kinds?: readonly string[];
  readonly relativePath?: string;
  readonly file?: string;
  readonly startLine?: number;
  readonly startColumn?: number;
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
    file: overrides.file ?? '/repo/src/db.ts',
    relativePath: overrides.relativePath ?? 'src/db.ts',
    range: {
      start: { line: overrides.startLine ?? 12, column: overrides.startColumn ?? 5 },
      end: { line: overrides.startLine ?? 12, column: (overrides.startColumn ?? 5) + 15 },
    },
    functionId: 'src/db.ts::handler',
    proof: overrides.proof ?? [],
  };
}

/** 解析結果を組み立てる。 */
function makeResult(overrides: {
  readonly findings?: readonly Finding[];
  readonly diagnostics?: readonly Diagnostic[];
  readonly files?: readonly SourceFileInfo[];
  readonly truncated?: readonly string[];
}): AnalysisResult {
  return {
    schemaVersion: 1,
    tool: {
      name: 'shirokuma-sast',
      version: '0.1.0',
      engineVersion: '0.1.0',
      configOrigin: 'builtin',
    },
    files: overrides.files ?? [],
    findings: overrides.findings ?? [],
    stats: {
      filesScanned: 3,
      functionsAnalysed: 12,
      flowNodes: 34,
      flowEdges: 40,
      iterations: 7,
      truncated: overrides.truncated ?? [],
    },
    diagnostics: overrides.diagnostics ?? [],
  };
}

/** ANSI エスケープを除去する（色が構造を変えていないことの検証に使う）。 */
function stripAnsi(text: string): string {
  return text.replace(/\u001b\[[0-9;]*m/gu, '');
}

describe('pretty レポータ', () => {
  it('検出がゼロのときは「検出なし」を 1 行だけ出す', () => {
    const out = createPrettyReporter().render(makeResult({}));

    expect(out.split('\n').filter((line) => line !== '')).toHaveLength(1);
    expect(out).toContain('検出なし');
    expect(out).toContain('3 ファイル / 12 関数');
    expect(out).not.toContain('\u001b');
  });

  it('color:false（既定）では ANSI を含まず、color:true では含む', () => {
    const result = makeResult({ findings: [makeFinding({})] });

    expect(createPrettyReporter().render(result)).not.toContain('\u001b');
    expect(createPrettyReporter({ color: true }).render(result)).toContain('\u001b[');
  });

  it('色付き出力から ANSI を除くと色なし出力と完全に一致する', () => {
    const result = makeResult({
      findings: [makeFinding({ proof: makeProof() }), makeFinding({ ruleId: 'xss', severity: 'warning' })],
    });
    const plain = createPrettyReporter().render(result);
    const colored = createPrettyReporter({ color: true }).render(result);

    expect(stripAnsi(colored)).toBe(plain);
  });

  it('重要度・ルール ID・位置・メッセージを検出ごとに出す', () => {
    const out = createPrettyReporter().render(makeResult({ findings: [makeFinding({})] }));
    const lines = out.split('\n');

    expect(lines[0]).toBe('shirokuma-sast 0.1.0 — 検出 1 件（error 1 / warning 0 / note 0）');
    expect(lines[2]).toBe('[error] sql-injection  src/db.ts:12:5');
    expect(lines[3]).toBe('  SQL 文字列の連結に外部入力が混入しています');
  });

  it('advice と CWE を補助情報として出す', () => {
    const out = createPrettyReporter().render(
      makeResult({
        findings: [makeFinding({ advice: 'プレースホルダを使ってください。', cwe: ['CWE-89'] })],
      }),
    );

    expect(out).toContain('advice: プレースホルダを使ってください。');
    expect(out).toContain('cwe: CWE-89');
  });

  it('汚染経路をツリーで描画し、最後のステップを sink にする', () => {
    const out = createPrettyReporter().render(
      makeResult({ findings: [makeFinding({ proof: makeProof() })] }),
    );

    expect(out).toContain('├─ source');
    expect(out).toContain('├─ propagate');
    expect(out).toContain('├─ sanitize');
    expect(out).toMatch(/└─ sink\s+src\/db\.ts:12:5\s+db\.query\(sql\)$/mu);
    // ステップのパスはプロジェクトルートからの相対へ短縮される
    expect(out).not.toContain('/repo/src/db.ts');
  });

  it('maxProofSteps で中間ステップだけを省略し、source と sink は残す', () => {
    const out = createPrettyReporter({ maxProofSteps: 2 }).render(
      makeResult({ findings: [makeFinding({ proof: makeProof() })] }),
    );

    expect(out).toContain('source');
    expect(out).toMatch(/└─ sink/u);
    expect(out).toContain('… 残り 2 ステップを省略');
    expect(out).not.toContain('propagate');
  });

  it('maxProofSteps: 0 では経路を 1 行の省略表示にする', () => {
    const out = createPrettyReporter({ maxProofSteps: 0 }).render(
      makeResult({ findings: [makeFinding({ proof: makeProof() })] }),
    );

    expect(out).toContain('… 残り 4 ステップを省略');
    expect(out).not.toContain('source');
  });

  it('制御文字を可視化し、端末への ANSI 注入を防ぐ', () => {
    const out = createPrettyReporter().render(
      makeResult({
        findings: [
          makeFinding({
            ruleId: 'evil\u001b[2J',
            message: '改行\nと ESC \u001b[31m',
          }),
        ],
      }),
    );

    expect(out).not.toContain('\u001b');
    expect(out).toContain('evil\\x1b[2J');
    expect(out).toContain('改行\\nと ESC \\x1b[31m');
  });

  it('経路が空でも落ちず、経路情報なしと出す', () => {
    const out = createPrettyReporter().render(makeResult({ findings: [makeFinding({})] }));

    expect(out).toContain('└─ (経路情報なし)');
  });

  it('サマリに件数・ファイル数・統計・打ち切りを出す', () => {
    const out = createPrettyReporter().render(
      makeResult({
        findings: [
          makeFinding({}),
          makeFinding({ id: 'xss:src/view.ts:4:3', ruleId: 'xss', severity: 'warning', relativePath: 'src/view.ts' }),
          makeFinding({ id: 'note:src/a.ts:1:1', ruleId: 'weak-hash', severity: 'note', relativePath: 'src/a.ts' }),
        ],
        truncated: ['src/a.ts::deepRecursion'],
      }),
    );

    expect(out).toContain('── サマリ');
    expect(out).toMatch(/検出\s+: 3 件（error 1 \/ warning 1 \/ note 1）/u);
    expect(out).toMatch(/ファイル\s+: 3 件をスキャン、3 件で検出/u);
    expect(out).toMatch(/関数\s+: 12 件を解析（iterations 7）/u);
    expect(out).toContain('ノード 34 / エッジ 40');
    expect(out).toContain('打ち切り');
    expect(out).toContain('src/a.ts::deepRecursion');
  });

  it('診断を重要度つきで表示する', () => {
    const out = createPrettyReporter().render(
      makeResult({
        findings: [makeFinding({})],
        diagnostics: [
          { level: 'warning', message: '解析できませんでした', file: 'src/broken.ts', range: { start: { line: 3, column: 1 }, end: { line: 3, column: 2 } } },
          { level: 'info', message: '3 ファイルを検出' },
        ],
      }),
    );

    expect(out).toContain('診断 2 件:');
    expect(out).toContain('[warning] src/broken.ts:3:1 解析できませんでした');
    expect(out).toContain('[info] 3 ファイルを検出');
    expect(out).toMatch(/診断\s+: info 1 \/ warning 1 \/ error 0/u);
  });

  it('同じ入力に対して常に同一の文字列を返す', () => {
    const result = makeResult({
      findings: [makeFinding({ proof: makeProof() }), makeFinding({ ruleId: 'xss', severity: 'note' })],
      diagnostics: [{ level: 'error', message: 'boom' }],
    });
    const reporter = createPrettyReporter({ color: true });

    expect(reporter.render(result)).toBe(reporter.render(result));
  });
});
