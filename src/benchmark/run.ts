/**
 * 検出精度ベンチマーク。
 *
 * `benchmarks/manifest.json` の教師データと実際の検出結果を突き合わせ、
 * 適合率（precision）・再現率（recall）・F1 を計算する。
 *
 * 指標の定義:
 * - **TP**: 脆弱とラベルした箇所に対して、同じ系統の検出が許容行数内で出た
 * - **FP**: ラベルの無い箇所に出た検出、または系統が違う検出
 * - **FN**: 脆弱とラベルした箇所に検出が出なかった
 *
 * 「安全とラベルした箇所に検出が出た場合」も FP として数える。
 * これにより、サニタイザを理解しているかどうかが指標に現れる。
 *
 * 実行: npm run bench（コンパイル済みの dist を使う）
 */
import { readFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { resolveConfig } from '../config/loader.js';
import { scan } from '../engine.js';
import type { AnalysisResult, Finding } from '../types.js';

// コンパイル後は dist/benchmark/ に置かれるため、リポジトリ直下は 2 つ上。
const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');
const BENCH_ROOT = path.join(ROOT, 'benchmarks');
const REPORTS = path.join(ROOT, 'reports');

interface Case {
  readonly file: string;
  readonly line: number;
  readonly note: string;
  readonly family?: string;
  readonly cwe?: string;
}

interface Manifest {
  readonly schemaVersion: number;
  readonly tolerance: number;
  readonly families: Readonly<Record<string, string>>;
  readonly vulnerable: readonly Case[];
  readonly clean: readonly Case[];
}

interface Metrics {
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly falseNegatives: number;
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
}

interface CaseOutcome {
  readonly file: string;
  readonly line: number;
  readonly family: string;
  readonly detected: boolean;
  readonly matchedRule: string | undefined;
  readonly note: string;
}

interface Report {
  /** レポート形式のバージョン。内容が変わったら上げる。 */
  readonly reportVersion: 1;
  readonly tool: string;
  readonly overall: Metrics;
  readonly byFamily: Readonly<Record<string, Metrics>>;
  readonly missed: readonly CaseOutcome[];
  readonly falsePositives: readonly { readonly file: string; readonly line: number; readonly ruleId: string; readonly message: string }[];
  readonly totals: { readonly findings: number; readonly files: number; readonly functions: number };
  /**
   * 解析時間（ミリ秒）。環境依存のためファイルには保存しない。
   * 実行のたびに値が変わると、成果物が再現しなくなるため。
   */
  readonly millis: number | null;
}

/** 系統の判定順。複数のタグを持つ検出（例: `$where` は code と nosql の両方）に対応する。 */
const FAMILY_ORDER = ['sql', 'html', 'command', 'path', 'code', 'nosql', 'url'] as const;

/** 検出が持つ系統タグの一覧。 */
function familiesOf(finding: Finding): readonly string[] {
  const kinds = new Set(finding.kinds);
  const matched = FAMILY_ORDER.filter((candidate) => kinds.has(candidate));
  return matched.length > 0 ? matched : ['unknown'];
}

/**
 * 集計用の代表系統。
 * 1 つの検出が複数の系統に属する場合（`$where` は code と nosql）、
 * 集計では先に定義された系統へ寄せる。
 */
function familyOf(finding: Finding): string {
  return familiesOf(finding)[0] ?? 'unknown';
}

function metrics(tp: number, fp: number, fn: number): Metrics {
  const precision = tp + fp === 0 ? 0 : tp / (tp + fp);
  const recall = tp + fn === 0 ? 0 : tp / (tp + fn);
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
  return {
    truePositives: tp,
    falsePositives: fp,
    falseNegatives: fn,
    precision: round(precision),
    recall: round(recall),
    f1: round(f1),
  };
}

function round(value: number): number {
  return Math.round(value * 1000) / 1000;
}

async function main(): Promise<void> {
  const manifest = JSON.parse(await readFile(path.join(BENCH_ROOT, 'manifest.json'), 'utf8')) as Manifest;
  const config = await resolveConfig({ root: BENCH_ROOT, builtinOnly: true });

  const started = Date.now();
  const result: AnalysisResult = await scan({ root: BENCH_ROOT, config });
  const millis = Date.now() - started;

  // 検出をファイルごとに索引化し、同時に系統も求めておく。
  const findingsByFile = new Map<string, Finding[]>();
  const familyByFindingId = new Map<string, string>();
  for (const finding of result.findings) {
    const bucket = findingsByFile.get(finding.relativePath) ?? [];
    bucket.push(finding);
    findingsByFile.set(finding.relativePath, bucket);
    familyByFindingId.set(finding.id, familyOf(finding));
  }

  const consumed = new Set<string>();
  const missed: CaseOutcome[] = [];
  const perFamily = new Map<string, { tp: number; fp: number; fn: number }>();

  const bucketFor = (family: string): { tp: number; fp: number; fn: number } => {
    const existing = perFamily.get(family) ?? { tp: 0, fp: 0, fn: 0 };
    perFamily.set(family, existing);
    return existing;
  };

  let truePositives = 0;
  let falseNegatives = 0;

  // 正例: 同じ系統の検出が許容行数内にあれば TP。無ければ FN。
  for (const testCase of manifest.vulnerable) {
    const family = testCase.family ?? 'unknown';
    const candidates = findingsByFile.get(testCase.file) ?? [];
    const hit = candidates.find(
      (finding) =>
        familiesOf(finding).includes(family) &&
        Math.abs(finding.range.start.line - testCase.line) <= manifest.tolerance &&
        !consumed.has(finding.id),
    );

    if (hit === undefined) {
      falseNegatives += 1;
      bucketFor(family).fn += 1;
      missed.push({
        file: testCase.file,
        line: testCase.line,
        family,
        detected: false,
        matchedRule: undefined,
        note: testCase.note,
      });
      continue;
    }

    truePositives += 1;
    bucketFor(family).tp += 1;
    consumed.add(hit.id);
  }

  // 負例: 正例として消費されなかった検出はすべて偽陽性。
  const falsePositiveFindings = result.findings.filter((finding) => !consumed.has(finding.id));
  for (const finding of falsePositiveFindings) {
    bucketFor(familyByFindingId.get(finding.id) ?? 'unknown').fp += 1;
  }
  const falsePositives = falsePositiveFindings.length;

  // 安全とラベルした箇所に出た検出は、特に重要な偽陽性なので別途数える。
  const cleanFalsePositives = manifest.clean.filter((testCase) =>
    (findingsByFile.get(testCase.file) ?? []).some(
      (finding) =>
        !consumed.has(finding.id) &&
        Math.abs(finding.range.start.line - testCase.line) <= manifest.tolerance,
    ),
  );

  const byFamily: Record<string, Metrics> = {};
  for (const [family, counts] of [...perFamily.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))) {
    byFamily[family] = metrics(counts.tp, counts.fp, counts.fn);
  }

  const report: Report = {
    reportVersion: 1,
    tool: `${result.tool.name}@${result.tool.version} (engine ${result.tool.engineVersion})`,
    overall: metrics(truePositives, falsePositives, falseNegatives),
    byFamily,
    missed,
    falsePositives: falsePositiveFindings.map((finding) => ({
      file: finding.relativePath,
      line: finding.range.start.line,
      ruleId: finding.ruleId,
      message: finding.message,
    })),
    totals: {
      findings: result.findings.length,
      files: result.stats.filesScanned,
      functions: result.stats.functionsAnalysed,
    },
    // 実行時間は標準出力にだけ出す（ファイルへ書くと再現性が壊れるため）。
    millis: null,
  };

  await mkdir(REPORTS, { recursive: true });
  await writeFile(path.join(REPORTS, 'benchmark.json'), `${JSON.stringify(report, null, 2)}\n`, 'utf8');
  await writeFile(path.join(REPORTS, 'benchmark.md'), renderMarkdown(report, manifest), 'utf8');

  console.log(
    `適合率 ${(report.overall.precision * 100).toFixed(1)}% / 再現率 ${(report.overall.recall * 100).toFixed(1)}% / F1 ${report.overall.f1.toFixed(3)}`,
  );
  console.log(`TP ${truePositives} / FP ${falsePositives} / FN ${falseNegatives}（安全側での誤検出 ${cleanFalsePositives.length} 件）`);
  console.log(`検出 ${report.totals.findings} 件 / ${report.totals.files} ファイル / ${report.totals.functions} 関数 / ${millis}ms`);
  console.log('レポート: reports/benchmark.json, reports/benchmark.md');

  if (missed.length > 0) {
    console.log('\n検出できなかった箇所:');
    for (const item of missed) {
      console.log(`  - ${item.file}:${item.line} [${item.family}] ${item.note}`);
    }
  }
  if (report.falsePositives.length > 0) {
    console.log('\n過剰検出:');
    for (const item of report.falsePositives) {
      console.log(`  - ${item.file}:${item.line} ${item.ruleId} ${item.message}`);
    }
  }
}

function renderMarkdown(report: Report, manifest: Manifest): string {
  const lines: string[] = [];
  lines.push('# 検出精度ベンチマーク');
  lines.push('');
  lines.push(`ツール: \`${report.tool}\``);
  lines.push('');
  lines.push('## 総合');
  lines.push('');
  lines.push('| 指標 | 値 |');
  lines.push('| --- | --- |');
  lines.push(`| 適合率 (precision) | ${(report.overall.precision * 100).toFixed(1)}% |`);
  lines.push(`| 再現率 (recall) | ${(report.overall.recall * 100).toFixed(1)}% |`);
  lines.push(`| F1 | ${report.overall.f1.toFixed(3)} |`);
  lines.push(`| 真陽性 / 偽陽性 / 偽陰性 | ${report.overall.truePositives} / ${report.overall.falsePositives} / ${report.overall.falseNegatives} |`);
  lines.push('');
  lines.push(`対象: ${report.totals.files} ファイル / ${report.totals.functions} 関数`);
  lines.push(`教師データ: 脆弱 ${manifest.vulnerable.length} 箇所 + 安全 ${manifest.clean.length} 箇所（行の許容差 ${manifest.tolerance} 行）`);
  lines.push('');
  lines.push('## 系統別');
  lines.push('');
  lines.push('| 系統 | 内容 | 適合率 | 再現率 | F1 | TP/FP/FN |');
  lines.push('| --- | --- | --- | --- | --- | --- |');
  for (const [family, value] of Object.entries(report.byFamily)) {
    const description = manifest.families[family] ?? family;
    lines.push(
      `| ${family} | ${description} | ${(value.precision * 100).toFixed(1)}% | ${(value.recall * 100).toFixed(1)}% | ${value.f1.toFixed(3)} | ${value.truePositives}/${value.falsePositives}/${value.falseNegatives} |`,
    );
  }
  lines.push('');
  lines.push('## 検出できなかった箇所（偽陰性）');
  lines.push('');
  if (report.missed.length === 0) {
    lines.push('なし。');
  } else {
    lines.push('| ファイル | 行 | 系統 | 内容 |');
    lines.push('| --- | --- | --- | --- |');
    for (const item of report.missed) {
      lines.push(`| \`${item.file}\` | ${item.line} | ${item.family} | ${item.note} |`);
    }
  }
  lines.push('');
  lines.push('## 過剰検出（偽陽性）');
  lines.push('');
  if (report.falsePositives.length === 0) {
    lines.push('なし。');
  } else {
    lines.push('| ファイル | 行 | ルール | メッセージ |');
    lines.push('| --- | --- | --- | --- |');
    for (const item of report.falsePositives) {
      lines.push(`| \`${item.file}\` | ${item.line} | ${item.ruleId} | ${item.message} |`);
    }
  }
  lines.push('');
  lines.push('> この表は `npm run bench` で再生成される。数値は手で書かず、必ず実行結果から取ること。');
  lines.push('> レポートは決定的に生成される（日時・実行時間を含めない）ため、');
  lines.push('> 指標が変わっていなければ再実行しても差分が出ない。');
  lines.push('');
  return lines.join('\n');
}

await main();
