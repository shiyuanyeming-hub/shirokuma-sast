/**
 * ベンチマーク結果を README へ埋め込む。
 *
 * 数値を手で書き写すと必ず古くなる。`npm run bench` の出力を
 * そのまま README の MARKER 間へ流し込むことで、
 * 「ドキュメントに書いてある数字」と「実際に測った数字」を一致させる。
 *
 * 使い方:
 *   npm run bench          # reports/benchmark.json を生成
 *   npm run bench:embed    # README の MARKER 間を更新
 */
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..', '..');

const START = '<!-- BENCHMARK:START -->';
const END = '<!-- BENCHMARK:END -->';

interface Metrics {
  readonly precision: number;
  readonly recall: number;
  readonly f1: number;
  readonly truePositives: number;
  readonly falsePositives: number;
  readonly falseNegatives: number;
}

interface Report {
  readonly generatedAt: string;
  readonly overall: Metrics;
  readonly byFamily: Readonly<Record<string, Metrics>>;
  readonly missed: readonly { readonly file: string; readonly line: number; readonly note: string }[];
  readonly falsePositives: readonly { readonly file: string; readonly line: number; readonly ruleId: string }[];
  readonly totals: { readonly files: number; readonly functions: number; readonly millis: number; readonly findings: number };
}

const pct = (value: number): string => `${(value * 100).toFixed(1)}%`;

/** README の言語。埋め込む見出しを切り替える。 */
type Lang = 'ja' | 'en';

/** 埋め込む見出しの文言。言語ごとに差し替える。 */
interface Labels {
  readonly metric: string;
  readonly value: string;
  readonly precision: string;
  readonly recall: string;
  readonly counts: string;
  readonly byFamily: string;
  readonly family: string;
  readonly remaining: string;
  readonly none: string;
  readonly falseNegative: string;
  readonly falsePositive: string;
  readonly scope: (files: number, functions: number, millis: number, vulnerable: number, clean: number) => string;
  readonly updated: (date: string) => string;
}

const LABELS: Record<Lang, Labels> = {
  ja: {
    metric: '指標',
    value: '値',
    precision: '適合率 (precision)',
    recall: '再現率 (recall)',
    counts: '真陽性 / 偽陽性 / 偽陰性',
    byFamily: '系統別:',
    family: '系統',
    remaining: '残っている誤り（隠さずに書く）:',
    none: '- なし。',
    falseNegative: '偽陰性',
    falsePositive: '偽陽性',
    scope: (files, functions, millis, vulnerable, clean) =>
      `対象: ${files} ファイル / ${functions} 関数 / ${millis}ms。教師データは脆弱 ${vulnerable} 箇所＋安全 ${clean} 箇所。`,
    updated: (date) => `最終更新: ${date}（\`npm run bench\` で再現可能）`,
  },
  en: {
    metric: 'Metric',
    value: 'Value',
    precision: 'Precision',
    recall: 'Recall',
    counts: 'True / false positives / false negatives',
    byFamily: 'By vulnerability family:',
    family: 'Family',
    remaining: 'Remaining errors (stated plainly):',
    none: '- None.',
    falseNegative: 'False negative',
    falsePositive: 'False positive',
    scope: (files, functions, millis, vulnerable, clean) =>
      `Scope: ${files} files / ${functions} functions / ${millis}ms. Corpus: ${vulnerable} vulnerable and ${clean} safe cases.`,
    updated: (date) => `Last updated: ${date} (reproducible via \`npm run bench\`)`,
  },
};

/** README に差し込む本文を組み立てる。 */
function render(report: Report, vulnerableCount: number, cleanCount: number, lang: Lang): string {
  const label = LABELS[lang];
  const lines: string[] = [];
  lines.push('');
  lines.push(`| ${label.metric} | ${label.value} |`);
  lines.push('| --- | --- |');
  lines.push(`| ${label.precision} | **${pct(report.overall.precision)}** |`);
  lines.push(`| ${label.recall} | **${pct(report.overall.recall)}** |`);
  lines.push(`| F1 | **${report.overall.f1.toFixed(3)}** |`);
  lines.push(
    `| ${label.counts} | ${report.overall.truePositives} / ${report.overall.falsePositives} / ${report.overall.falseNegatives} |`,
  );
  lines.push('');
  lines.push(
    label.scope(report.totals.files, report.totals.functions, report.totals.millis, vulnerableCount, cleanCount),
  );
  lines.push('');
  lines.push(label.byFamily);
  lines.push('');
  lines.push(`| ${label.family} | ${label.precision} | ${label.recall} | TP/FP/FN |`);
  lines.push('| --- | --- | --- | --- |');
  for (const [family, value] of Object.entries(report.byFamily)) {
    lines.push(
      `| \`${family}\` | ${pct(value.precision)} | ${pct(value.recall)} | ${value.truePositives}/${value.falsePositives}/${value.falseNegatives} |`,
    );
  }
  lines.push('');
  lines.push(label.remaining);
  lines.push('');
  if (report.missed.length === 0 && report.falsePositives.length === 0) {
    lines.push(label.none);
  } else {
    for (const item of report.missed) {
      lines.push(`- **${label.falseNegative}**: \`${item.file}:${item.line}\` — ${item.note}`);
    }
    for (const item of report.falsePositives) {
      lines.push(`- **${label.falsePositive}**: \`${item.file}:${item.line}\` (\`${item.ruleId}\`)`);
    }
  }
  lines.push('');
  lines.push(label.updated(report.generatedAt.slice(0, 10)));
  lines.push('');
  return lines.join('\n');
}

async function embed(readmePath: string, body: string): Promise<boolean> {
  const original = await readFile(readmePath, 'utf8');
  const startIndex = original.indexOf(START);
  const endIndex = original.indexOf(END);
  if (startIndex === -1 || endIndex === -1) {
    console.warn(`マーカーが見つかりません: ${readmePath}`);
    return false;
  }
  const updated = `${original.slice(0, startIndex + START.length)}\n${body}${original.slice(endIndex)}`;
  if (updated === original) {
    return false;
  }
  await writeFile(readmePath, updated, 'utf8');
  return true;
}

const report = JSON.parse(await readFile(path.join(ROOT, 'reports', 'benchmark.json'), 'utf8')) as Report;
const manifest = JSON.parse(await readFile(path.join(ROOT, 'benchmarks', 'manifest.json'), 'utf8')) as {
  vulnerable: unknown[];
  clean: unknown[];
};

const targets: readonly { readonly file: string; readonly lang: Lang }[] = [
  { file: 'README.md', lang: 'ja' },
  { file: 'README.en.md', lang: 'en' },
];

for (const target of targets) {
  const absolute = path.join(ROOT, target.file);
  try {
    const changed = await embed(absolute, render(report, manifest.vulnerable.length, manifest.clean.length, target.lang));
    console.log(`${changed ? '更新' : '変更なし'}: ${target.file}`);
  } catch {
    console.log(`スキップ（未作成）: ${target.file}`);
  }
}
