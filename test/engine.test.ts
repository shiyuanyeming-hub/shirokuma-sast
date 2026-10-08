/**
 * パイプライン全体の統合テスト。
 *
 * 探索 → IR 構築 → ルール適用 → データフロー解析 → レポートまでを
 * 実際に通し、各段の接続が壊れていないことを確認する。
 * 単体テストでは見つからない「層のつなぎ目の不整合」を検出するのが目的。
 */
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resolveConfig } from '../src/config/loader.js';
import { scan, shouldFail, summarize, countBySeverity } from '../src/engine.js';
import { discoverFiles } from '../src/discovery.js';
import { createReporter, createSarifReporter } from '../src/reporters/index.js';
import type { AnalysisResult } from '../src/types.js';

let root: string;

/** フィクスチャ用のファイルを書く。 */
async function fixture(relativePath: string, contents: string): Promise<void> {
  const absolute = path.join(root, relativePath);
  await mkdir(path.dirname(absolute), { recursive: true });
  await writeFile(absolute, contents, 'utf8');
}

beforeAll(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'shirokuma-engine-'));
  await fixture(
    'src/app.ts',
    [
      "import express from 'express';",
      '',
      'const app = express();',
      '',
      "app.get('/users', (req, res) => {",
      '  const id = req.query.id;',
      "  const sql = 'SELECT * FROM users WHERE id = ' + id;",
      '  db.query(sql, (err, rows) => res.json(rows));',
      '});',
      '',
      "app.get('/safe', (req, res) => {",
      '  const id = req.query.id;',
      "  db.query('SELECT * FROM users WHERE id = $1', [id], (err, rows) => res.json(rows));",
      '});',
      '',
    ].join('\n'),
  );
  await fixture(
    'src/helper.ts',
    [
      'export function pick(text: string): string {',
      "  return text.replace(/x/g, 'y');",
      '}',
      '',
    ].join('\n'),
  );
  await fixture(
    'src/nested/direct.ts',
    [
      "import { exec } from 'child_process';",
      '',
      'export function run(req: any): void {',
      '  const target = req.query.host;',
      "  exec('ping -c 1 ' + target);",
      '}',
      '',
    ].join('\n'),
  );
  await fixture('src/generated/skipme.ts', "const x = 'nothing here';\n");
  await fixture('node_modules/pkg/index.ts', "const y = 'should be ignored';\n");
});

afterAll(async () => {
  if (root !== undefined) {
    await rm(root, { recursive: true, force: true });
  }
});

describe('ファイル探索', () => {
  it('対象拡張子だけを辞書順で返す', async () => {
    const { files } = await discoverFiles({ root });
    const relatives = files.map((file) => path.relative(root, file).split(path.sep).join('/'));
    expect(relatives).toEqual(['src/app.ts', 'src/generated/skipme.ts', 'src/helper.ts', 'src/nested/direct.ts']);
  });

  it('node_modules を既定で除外する', async () => {
    const { files } = await discoverFiles({ root });
    expect(files.some((file) => file.includes('node_modules'))).toBe(false);
  });

  it('exclude で追加除外できる', async () => {
    const { files } = await discoverFiles({ root, exclude: ['src/generated'] });
    expect(files.some((file) => file.includes('generated'))).toBe(false);
  });

  it('include で絞り込める', async () => {
    const { files } = await discoverFiles({ root, include: ['src/*.ts'] });
    const relatives = files.map((file) => path.relative(root, file).split(path.sep).join('/'));
    expect(relatives).toEqual(['src/app.ts', 'src/helper.ts']);
  });

  it('存在しないルートはエラー診断を返す（例外にしない）', async () => {
    const { files, diagnostics } = await discoverFiles({ root: path.join(root, 'does-not-exist') });
    expect(files).toEqual([]);
    expect(diagnostics.some((diagnostic) => diagnostic.level === 'error')).toBe(true);
  });
});

describe('スキャン全体', () => {
  let result: AnalysisResult;

  beforeAll(async () => {
    const config = await resolveConfig({ root, builtinOnly: true });
    result = await scan({ root, config });
  });

  it('SQL インジェクションを検出し、安全なプレースホルダ版は検出しない', () => {
    const appFindings = result.findings.filter((finding) => finding.relativePath === 'src/app.ts');
    const sqlFindings = appFindings.filter((finding) => finding.kinds.includes('sql'));
    expect(sqlFindings.length).toBeGreaterThanOrEqual(1);
    // 安全な側（プレースホルダ）は 12 行目。検出がそこを指していないこと。
    expect(sqlFindings.every((finding) => finding.range.start.line !== 12)).toBe(true);
  });

  it('コマンドインジェクションを検出する', () => {
    const commandFindings = result.findings.filter((finding) => finding.kinds.includes('command'));
    expect(commandFindings.length).toBeGreaterThanOrEqual(1);
    expect(commandFindings.some((finding) => finding.relativePath === 'src/nested/direct.ts')).toBe(true);
  });

  it('検出は決定的な順序で並ぶ（ファイル → 行 → 列 → ruleId）', () => {
    const keys = result.findings.map((finding) => [
      finding.relativePath,
      finding.range.start.line,
      finding.range.start.column,
      finding.ruleId,
    ]);
    const sorted = [...keys].sort((a, b) => {
      const [af, al, ac, ar] = a as [string, number, number, string];
      const [bf, bl, bc, br] = b as [string, number, number, string];
      if (af !== bf) return af < bf ? -1 : 1;
      if (al !== bl) return al - bl;
      if (ac !== bc) return ac - bc;
      return ar < br ? -1 : ar > br ? 1 : 0;
    });
    expect(keys).toEqual(sorted);
  });

  it('各検出はソースからシンクまでの根拠（proof）を持つ', () => {
    expect(result.findings.length).toBeGreaterThan(0);
    for (const finding of result.findings) {
      expect(finding.proof.length).toBeGreaterThanOrEqual(2);
      expect(finding.proof[0]?.role).toBe('source');
      expect(finding.proof[finding.proof.length - 1]?.role).toBe('sink');
    }
  });

  it('proof の位置は実ファイルの行と整合する', () => {
    for (const finding of result.findings) {
      for (const step of finding.proof) {
        expect(step.range.start.line).toBeGreaterThanOrEqual(1);
        expect(step.range.start.column).toBeGreaterThanOrEqual(1);
      }
    }
  });

  it('検出 ID は安定している（ruleId:ファイル:行:列）', () => {
    for (const finding of result.findings) {
      expect(finding.id).toBe(
        `${finding.ruleId}:${finding.relativePath}:${finding.range.start.line}:${finding.range.start.column}`,
      );
    }
  });

  it('統計が埋まる', () => {
    expect(result.stats.filesScanned).toBe(4);
    expect(result.stats.functionsAnalysed).toBeGreaterThan(0);
    expect(result.stats.flowNodes).toBeGreaterThan(0);
    expect(result.stats.flowEdges).toBeGreaterThan(0);
    expect(result.stats.iterations).toBeGreaterThan(0);
  });

  it('解析は決定的である（2 回実行して同じ検出）', async () => {
    const config = await resolveConfig({ root, builtinOnly: true });
    const second = await scan({ root, config });
    expect(second.findings.map((finding) => finding.id)).toEqual(result.findings.map((finding) => finding.id));
  });

  it('重要度ごとの件数とサマリ文字列を返す', () => {
    const counts = countBySeverity(result.findings);
    expect(counts.error + counts.warning + counts.note).toBe(result.findings.length);
    expect(summarize(result)).toContain('検出');
  });

  it('CI ゲートは重要度しきい値で判定する', () => {
    expect(shouldFail(result, 'error')).toBe(true);
    expect(shouldFail(result, 'none')).toBe(false);
  });
});

describe('レポータ連携', () => {
  let result: AnalysisResult;

  beforeAll(async () => {
    const config = await resolveConfig({ root, builtinOnly: true });
    result = await scan({ root, config });
  });

  it('pretty は検出と根拠を出力する', () => {
    const output = createReporter('pretty').render(result);
    expect(output).toContain(result.findings[0]?.ruleId ?? '');
    expect(output).toMatch(/source/);
  });

  it('json はパースでき、検出件数が一致する', () => {
    const parsed = JSON.parse(createReporter('json').render(result)) as { findings: unknown[] };
    expect(parsed.findings.length).toBe(result.findings.length);
  });

  it('sarif は 2.1.0 として妥当で、codeFlows に経路が入る', () => {
    const sarif = JSON.parse(createSarifReporter().render(result)) as {
      version: string;
      runs: { results: { ruleId: string; codeFlows?: unknown[] }[]; tool: { driver: { rules: unknown[] } } }[];
    };
    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0];
    expect(run).toBeDefined();
    expect(run?.tool.driver.rules.length).toBeGreaterThan(0);
    expect(run?.results.length).toBe(result.findings.length);
    expect(run?.results.every((entry) => entry.codeFlows !== undefined)).toBe(true);
  });

  it('markdown は表と見出しを含む', () => {
    const output = createReporter('markdown').render(result);
    expect(output).toContain('#');
    expect(output).toContain('|');
  });

  it('同じ結果からは同じレポート文字列が出る', () => {
    for (const format of ['pretty', 'json', 'sarif', 'markdown'] as const) {
      const reporter = createReporter(format);
      expect(reporter.render(result)).toBe(reporter.render(result));
    }
  });
});

describe('設定との連携', () => {
  it('kinds で報告するタグを絞り込める', async () => {
    const config = await resolveConfig({ root, builtinOnly: true });
    const onlyCommand = await scan({
      root,
      config: { ...config, analysis: { ...config.analysis, kinds: ['command'] } },
    });
    expect(onlyCommand.findings.length).toBeGreaterThan(0);
    expect(onlyCommand.findings.every((finding) => finding.kinds.includes('command'))).toBe(true);
  });

  it('ignorePaths でファイルを除外できる', async () => {
    const config = await resolveConfig({ root, builtinOnly: true });
    const filtered = await scan({
      root,
      config: { ...config, rules: { ...config.rules, ignorePaths: ['src/nested'] } },
    });
    expect(filtered.findings.some((finding) => finding.relativePath.startsWith('src/nested'))).toBe(false);
  });

  it('設定の出所が origin に入る', async () => {
    const config = await resolveConfig({ root, builtinOnly: true });
    expect(config.origin).toBe('builtin');
    const result = await scan({ root, config });
    expect(result.tool.configOrigin).toBe('builtin');
  });
});
