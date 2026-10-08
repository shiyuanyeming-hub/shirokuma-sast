/**
 * CLI のテスト。
 *
 * 出力先を差し替えられる `run()` を直接呼ぶので、子プロセスを起動せずに
 * 終了コードと出力を検証できる（速く、環境に依存しない）。
 */
import { mkdtemp, mkdir, rm, writeFile, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { CliError, parseArgs, USAGE } from '../src/cli/args.js';
import { EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, run } from '../src/cli/scan-command.js';

interface Captured {
  readonly code: number;
  readonly stdout: string;
  readonly stderr: string;
}

async function cli(argv: readonly string[]): Promise<Captured> {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, {
    stdout: (text) => {
      stdout += text;
    },
    stderr: (text) => {
      stderr += text;
    },
  });
  return { code, stdout, stderr };
}

let root: string;

beforeAll(async () => {
  root = await mkdtemp(path.join(tmpdir(), 'shirokuma-cli-'));
  await mkdir(path.join(root, 'src'), { recursive: true });
  await writeFile(
    path.join(root, 'src', 'vulnerable.ts'),
    [
      "import express from 'express';",
      "import { exec } from 'child_process';",
      '',
      'const app = express();',
      '',
      "app.get('/x', (req, res) => {",
      '  const host = req.query.host;',
      "  exec('ping ' + host);",
      '  res.end();',
      '});',
      '',
    ].join('\n'),
    'utf8',
  );
  await writeFile(
    path.join(root, 'src', 'safe.ts'),
    ["import express from 'express';", '', 'const app = express();', '', "app.get('/y', (req, res) => {", "  res.json({ ok: true });", '});', ''].join('\n'),
    'utf8',
  );
});

afterAll(async () => {
  if (root !== undefined) {
    await rm(root, { recursive: true, force: true });
  }
});

describe('引数解析', () => {
  it('引数が無ければカレントディレクトリを解析する', () => {
    const command = parseArgs([]);
    expect(command).toMatchObject({ kind: 'scan', target: '.', format: 'pretty', failOn: 'error' });
  });

  it('`scan` の有無どちらでも受け付ける', () => {
    expect(parseArgs(['scan', 'src'])).toMatchObject({ kind: 'scan', target: 'src' });
    expect(parseArgs(['src'])).toMatchObject({ kind: 'scan', target: 'src' });
  });

  it('--format を解釈する（短縮形と = 形式を含む）', () => {
    expect(parseArgs(['-f', 'sarif'])).toMatchObject({ format: 'sarif' });
    expect(parseArgs(['--format=json'])).toMatchObject({ format: 'json' });
  });

  it('未知の --format はエラー', () => {
    expect(() => parseArgs(['--format', 'xml'])).toThrow(CliError);
  });

  it('--fail-on を解釈する', () => {
    expect(parseArgs(['--fail-on', 'warning'])).toMatchObject({ failOn: 'warning' });
    expect(parseArgs(['--fail-on=none'])).toMatchObject({ failOn: 'none' });
  });

  it('値を伴わないオプションはエラー', () => {
    expect(() => parseArgs(['--format'])).toThrow(/値が必要/);
    expect(() => parseArgs(['--config'])).toThrow(/値が必要/);
  });

  it('複数の --include / --exclude を蓄積する', () => {
    const command = parseArgs(['--include', 'src/*.ts', '--include', 'lib/*.ts', '--exclude', 'test']);
    expect(command).toMatchObject({ include: ['src/*.ts', 'lib/*.ts'], exclude: ['test'] });
  });

  it('--no-color と --quiet を解釈する', () => {
    expect(parseArgs(['--no-color', '--quiet'])).toMatchObject({ color: false, quiet: true });
  });

  it('--max-call-depth は非負整数のみ', () => {
    expect(parseArgs(['--max-call-depth', '5'])).toMatchObject({ maxCallDepth: 5 });
    expect(() => parseArgs(['--max-call-depth', '-1'])).toThrow(CliError);
  });

  it('--help と --version', () => {
    expect(parseArgs(['--help'])).toEqual({ kind: 'help' });
    expect(parseArgs(['-h'])).toEqual({ kind: 'help' });
    expect(parseArgs(['--version'])).toEqual({ kind: 'version' });
  });

  it('解析の途中でも --help が効く', () => {
    expect(parseArgs(['src', '--format', 'json', '--help'])).toEqual({ kind: 'help' });
  });

  it('rules コマンド', () => {
    expect(parseArgs(['rules'])).toEqual({ kind: 'rules', json: false });
    expect(parseArgs(['rules', '--json'])).toEqual({ kind: 'rules', json: true });
  });

  it('explain コマンドは <ファイル>:<行> を要求する', () => {
    expect(parseArgs(['explain', 'src/app.ts:42'])).toEqual({ kind: 'explain', file: 'src/app.ts', line: 42, json: false });
    expect(() => parseArgs(['explain'])).toThrow(/必要/);
    expect(() => parseArgs(['explain', 'src/app.ts'])).toThrow(/不正/);
    expect(() => parseArgs(['explain', 'src/app.ts:abc'])).toThrow(/行番号/);
  });

  it('未知のオプションはエラー', () => {
    expect(() => parseArgs(['--nope'])).toThrow(/未知のオプション/);
  });
});

describe('バージョンと使い方', () => {
  it('--version は終了コード 0 でバージョンを出す', async () => {
    const { code, stdout } = await cli(['--version']);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toMatch(/^0\.1\.0 /);
  });

  it('--help は使い方全文を出す', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toBe(USAGE);
    expect(stdout).toContain('終了コード');
  });

  it('引数エラーは終了コード 2 で使い方を出す', async () => {
    // エラーと使い方は stderr へ出す（パイプで本文と混ざらないようにするため）。
    const { code, stderr } = await cli(['--format', 'xml']);
    expect(code).toBe(EXIT_ERROR);
    expect(stderr).toContain('エラー');
    expect(stderr).toContain('使い方');
    expect(stderr).toContain('終了コード');
  });
});

describe('rules コマンド', () => {
  it('組み込みルールを一覧する', async () => {
    const { code, stdout } = await cli(['rules']);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toContain('組み込みルール');
    expect(stdout).toContain('ソース');
    expect(stdout).toContain('サニタイザ');
    expect(stdout).toContain('シンク');
  });

  it('--json はパースでき、3 分類を持つ', async () => {
    const { code, stdout } = await cli(['rules', '--json']);
    expect(code).toBe(EXIT_OK);
    const parsed = JSON.parse(stdout) as { sources: unknown[]; sanitizers: unknown[]; sinks: unknown[] };
    expect(parsed.sources.length).toBeGreaterThan(0);
    expect(parsed.sanitizers.length).toBeGreaterThan(0);
    expect(parsed.sinks.length).toBeGreaterThan(0);
  });
});

describe('scan コマンド', () => {
  it('脆弱なコードで終了コード 1 を返す', async () => {
    const { code, stdout } = await cli(['scan', root, '--no-color', '--quiet']);
    expect(code).toBe(EXIT_FINDINGS);
    expect(stdout).toContain('command-exec');
  });

  it('--fail-on none なら検出があっても終了コード 0', async () => {
    const { code } = await cli(['scan', root, '--fail-on', 'none', '--quiet']);
    expect(code).toBe(EXIT_OK);
  });

  it('安全なディレクトリなら検出なしで終了コード 0', async () => {
    const { code, stdout } = await cli(['scan', path.join(root, 'src', 'safe.ts'), '--quiet']);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toContain('検出なし');
  });

  it('--format json は機械可読な結果を出す', async () => {
    const { stdout } = await cli(['scan', root, '--format', 'json', '--quiet']);
    const parsed = JSON.parse(stdout) as { findings: unknown[]; tool: { name: string } };
    expect(parsed.tool.name).toBe('shirokuma-sast');
    expect(parsed.findings.length).toBeGreaterThan(0);
  });

  it('--format sarif は 2.1.0 を出す', async () => {
    const { stdout } = await cli(['scan', root, '--format', 'sarif', '--quiet']);
    const parsed = JSON.parse(stdout) as { version: string };
    expect(parsed.version).toBe('2.1.0');
  });

  it('--format markdown は表を出す', async () => {
    const { stdout } = await cli(['scan', root, '--format', 'markdown', '--quiet']);
    expect(stdout).toContain('|');
  });

  it('--output でファイルへ書き出す', async () => {
    const target = path.join(root, 'report.sarif');
    const { code, stdout } = await cli(['scan', root, '--format', 'sarif', '--output', target, '--fail-on', 'none', '--quiet']);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toContain('書き出しました');
    const written = JSON.parse(await readFile(target, 'utf8')) as { version: string };
    expect(written.version).toBe('2.1.0');
    await rm(target, { force: true });
  });

  it('存在しない対象は終了コード 2 で、理由を必ず知らせる', async () => {
    // --quiet でも失敗は握りつぶさない（CI が「脆弱性なし」と誤認しないため）。
    const { code, stderr } = await cli(['scan', path.join(root, 'nope'), '--quiet']);
    expect(code).toBe(EXIT_ERROR);
    expect(stderr).toContain('[error]');
    expect(stderr).toContain('解析ルートを開けませんでした');
  });

  it('--no-color なら ANSI エスケープを含まない', async () => {
    const { stdout } = await cli(['scan', root, '--no-color', '--quiet']);
    // eslint-disable-next-line no-control-regex
    expect(/\u001B\[/.test(stdout)).toBe(false);
  });
});

describe('explain コマンド', () => {
  it('指定位置の判定を出す', async () => {
    const file = path.join(root, 'src', 'vulnerable.ts');
    const { code, stdout } = await cli(['explain', `${file}:8`]);
    expect(code).toBe(EXIT_OK);
    expect(stdout).toContain('ソース');
    expect(stdout).toContain('シンク');
  });

  it('--json はパースできる', async () => {
    const file = path.join(root, 'src', 'vulnerable.ts');
    const { code, stdout } = await cli(['explain', `${file}:7`, '--json']);
    expect(code).toBe(EXIT_OK);
    const parsed = JSON.parse(stdout) as { line: number };
    expect(parsed.line).toBe(7);
  });
});
