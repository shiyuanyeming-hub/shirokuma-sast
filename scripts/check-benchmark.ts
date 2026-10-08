/**
 * ベンチマークの下限チェック（CI 用）。
 *
 * `npm run bench` と同じ測定を行い、適合率・再現率が下限を下回ったら
 * 終了コード 1 で失敗させる。数値を人が見張らなくても、
 * 「ルールを 1 つ足したら精度が落ちた」ことに CI が気づけるようにする。
 *
 * 下限は現状の実測値より少し低く設定してある。
 * 上げるときは、実際に測定してから上げること。
 */
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '..');

/** 許容する下限。実測値に余裕を持たせ、環境差で揺れても落ちないようにする。 */
const MIN_PRECISION = 0.7;
const MIN_RECALL = 0.85;

interface Report {
  readonly overall: { readonly precision: number; readonly recall: number; readonly f1: number };
  readonly missed: readonly unknown[];
}

const measured = spawnSync(process.execPath, [path.join(ROOT, 'dist', 'benchmark', 'run.js')], {
  cwd: ROOT,
  stdio: 'inherit',
});
if (measured.status !== 0) {
  console.error('\nベンチマークの実行に失敗しました。');
  process.exit(1);
}

const report = JSON.parse(await readFile(path.join(ROOT, 'reports', 'benchmark.json'), 'utf8')) as Report;

const failures: string[] = [];
if (report.overall.precision < MIN_PRECISION) {
  failures.push(`適合率 ${report.overall.precision} < 下限 ${MIN_PRECISION}`);
}
if (report.overall.recall < MIN_RECALL) {
  failures.push(`再現率 ${report.overall.recall} < 下限 ${MIN_RECALL}`);
}

if (failures.length > 0) {
  console.error('\n精度が下限を下回りました:');
  for (const failure of failures) {
    console.error(`  - ${failure}`);
  }
  console.error('\nreports/benchmark.md を確認し、ルールかテストデータを見直してください。');
  process.exit(1);
}

console.log(
  `\n精度チェック OK（適合率 >= ${MIN_PRECISION}、再現率 >= ${MIN_RECALL}）` +
    ` — 実測: P=${report.overall.precision} R=${report.overall.recall} F1=${report.overall.f1}`,
);
