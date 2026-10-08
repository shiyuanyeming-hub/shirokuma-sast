/**
 * 設定ローダの挙動を固定する。
 *
 * マージ規則（追記・後勝ち・ignorePaths の置換・analysis/output の浅いマージ）と、
 * 設定ファイル探索の優先順位、`ConfigError` のパス精度を検証する。
 */
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { ConfigError } from '../../src/config/contract.js';
import { CONFIG_FILE_CANDIDATES, resolveConfig, resolveRuleSet, ruleSetFromDocument } from '../../src/config/loader.js';
import { BUILTIN_SANITIZERS, BUILTIN_SINKS, BUILTIN_SOURCES, DEFAULT_IGNORE_PATHS } from '../../src/rules/builtin.js';
import type { ResolvedRuleSet, SinkSpec } from '../../src/types.js';

/** テスト用フィクスチャのディレクトリ。 */
const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');

/** フィクスチャのルートパスを作る。 */
function fixture(name: string): string {
  return path.join(FIXTURES, name);
}

/** `ConfigError` を捕まえるヘルパー。 */
async function configErrorOf(action: () => Promise<unknown>): Promise<ConfigError> {
  try {
    await action();
  } catch (error) {
    if (error instanceof ConfigError) return error;
    throw error;
  }
  throw new Error('ConfigError が投げられませんでした');
}

/** テスト用のシンクを作る。 */
function sink(id: string, overrides: Partial<SinkSpec> = {}): SinkSpec {
  return { id, call: 'run', kinds: ['sql'], severity: 'error', message: `${id} への到達`, ...overrides };
}

describe('CONFIG_FILE_CANDIDATES', () => {
  it('探索順は .shirokuma.yml → .shirokuma.yaml で固定される', () => {
    expect(CONFIG_FILE_CANDIDATES).toEqual(['.shirokuma.yml', '.shirokuma.yaml']);
  });
});

describe('resolveRuleSet', () => {
  it('索引（sinkById / sourceById / sanitizerById）を張る', () => {
    const rules = resolveRuleSet({
      sources: [{ id: 's', member: 'req.query', kinds: ['sql'] }],
      sanitizers: [{ id: 'z', call: 'escapeAll', kinds: ['html'] }],
      sinks: [sink('k')],
    });
    expect(rules.sinkById.get('k')?.id).toBe('k');
    expect(rules.sourceById.get('s')?.member).toBe('req.query');
    expect(rules.sanitizerById.get('z')?.call).toBe('escapeAll');
  });

  it('未指定のリストは空配列になる', () => {
    const rules = resolveRuleSet({});
    expect(rules.sources).toEqual([]);
    expect(rules.sanitizers).toEqual([]);
    expect(rules.sinks).toEqual([]);
    expect(rules.propagators).toEqual([]);
    expect(rules.ignorePaths).toEqual([]);
  });

  it('id の重複は後勝ちで、位置は最初の宣言のまま', () => {
    const onWarning = vi.fn();
    const rules = resolveRuleSet(
      { sinks: [sink('a'), sink('b'), sink('a', { severity: 'note', message: '上書き' })] },
      onWarning,
    );
    expect(rules.sinks.map((item) => item.id)).toEqual(['a', 'b']);
    expect(rules.sinks[0]?.severity).toBe('note');
    expect(rules.sinks[0]?.message).toBe('上書き');
    expect(onWarning).toHaveBeenCalledWith(expect.stringContaining('"a" が重複'), 'rules.sinks[2]');
  });

  it('kinds が空のサニタイザはソース／シンクのタグ語彙へ展開される', () => {
    const rules = resolveRuleSet({
      sources: [{ id: 's', member: 'req.query', kinds: ['sql'] }],
      sinks: [sink('k')],
      sanitizers: [{ id: 'z', call: 'neutralize', kinds: [] }],
    });
    expect(rules.sanitizers[0]?.kinds).toEqual(['sql']);
  });

  it('ソースもシンクも無ければタグ語彙全体へ展開される', () => {
    const rules = resolveRuleSet({ sanitizers: [{ id: 'z', call: 'neutralize', kinds: [] }] });
    expect(rules.sanitizers[0]?.kinds).toEqual(['code', 'command', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url']);
  });

  it('伝播規則の重複は 1 件に畳まれる', () => {
    const rules = resolveRuleSet({ propagators: [{ call: 'map' }, { call: 'map' }, { member: 'JSON.parse' }] });
    expect(rules.propagators).toEqual([{ call: 'map' }, { member: 'JSON.parse' }]);
  });

  it('ignorePaths は呼び出し元の配列を共有しない', () => {
    const input = ['**/a/**'];
    const rules = resolveRuleSet({ ignorePaths: input });
    expect(rules.ignorePaths).toEqual(input);
    expect(rules.ignorePaths).not.toBe(input);
  });

  it('severity が不正なら path 付きの ConfigError', () => {
    let caught: ConfigError | undefined;
    try {
      resolveRuleSet({ sinks: [sink('a'), sink('b', { severity: 'fatal' as SinkSpec['severity'] })] });
    } catch (error) {
      if (error instanceof ConfigError) caught = error;
    }
    expect(caught?.path).toBe('rules.sinks[1].severity');
  });

  it('id が無ければ path 付きの ConfigError', () => {
    let caught: ConfigError | undefined;
    try {
      resolveRuleSet({ sources: [{ kinds: ['sql'], member: 'req.query' } as unknown as ResolvedRuleSet['sources'][number]] });
    } catch (error) {
      if (error instanceof ConfigError) caught = error;
    }
    expect(caught?.path).toBe('rules.sources[0].id');
  });

  it('未知キーは警告だけを出して続行する', () => {
    const onWarning = vi.fn();
    const rules = resolveRuleSet(
      { sinks: [{ ...sink('a'), unknownField: true } as SinkSpec] },
      onWarning,
    );
    expect(rules.sinks).toHaveLength(1);
    expect(onWarning).toHaveBeenCalledWith(expect.stringContaining('unknownField'), 'rules.sinks[0].unknownField');
  });
});

describe('resolveConfig: 組み込み既定のみ', () => {
  it('設定ファイルが無ければ origin は builtin', async () => {
    const config = await resolveConfig({ root: fixture('none'), builtinOnly: true });
    expect(config.origin).toBe('builtin');
    expect(config.schemaVersion).toBe(1);
    expect(config.rules.sources.length).toBe(BUILTIN_SOURCES.length);
    expect(config.rules.ignorePaths).toEqual(DEFAULT_IGNORE_PATHS);
    expect(config.output).toEqual({ format: 'pretty', failOn: 'error' });
    expect(config.analysis).toEqual({ maxCallDepth: 3, maxIterations: 200, dedupe: true });
  });

  it('設定ファイルが無いディレクトリでも探索は失敗しない', async () => {
    const config = await resolveConfig({ root: fixture('none') });
    expect(config.origin).toBe('builtin');
  });
});

describe('resolveConfig: 設定ファイル探索', () => {
  it('探索で .shirokuma.yaml を見つけて origin に入れる', async () => {
    const config = await resolveConfig({ root: fixture('minimal') });
    expect(config.origin).toBe(path.join(fixture('minimal'), '.shirokuma.yaml'));
    expect(config.output.format).toBe('markdown');
  });

  it('候補が複数あれば CONFIG_FILE_CANDIDATES の順で先に見つかった方を使う', async () => {
    const config = await resolveConfig({ root: fixture('precedence') });
    expect(config.origin).toBe(path.join(fixture('precedence'), '.shirokuma.yml'));
    expect(config.output.format).toBe('json');
  });

  it('--config の相対パスは root から解決する', async () => {
    const config = await resolveConfig({ root: fixture('minimal'), configPath: '.shirokuma.yaml' });
    expect(config.output.format).toBe('markdown');
  });

  it('存在しない --config は ConfigError', async () => {
    const error = await configErrorOf(() => resolveConfig({ root: fixture('none'), configPath: 'missing.yml' }));
    expect(error.path).toBe('missing.yml');
    expect(error.message).toContain('見つかりません');
  });

  it('builtinOnly は探索を無効化する', async () => {
    const config = await resolveConfig({ root: fixture('full'), builtinOnly: true });
    expect(config.origin).toBe('builtin');
    expect(config.rules.sources.length).toBe(BUILTIN_SOURCES.length);
  });
});

describe('resolveConfig: マージ規則', () => {
  it('ルールは組み込みへ追記される', async () => {
    const config = await resolveConfig({ root: fixture('full') });
    expect(config.rules.sources.length).toBe(BUILTIN_SOURCES.length + 2);
    expect(config.rules.sanitizers.length).toBe(BUILTIN_SANITIZERS.length + 2);
    expect(config.rules.sinks.length).toBe(BUILTIN_SINKS.length + 1);
    expect(config.rules.sourceById.get('my-framework-query')?.kinds).toEqual(['sql', 'html']);
    expect(config.rules.sinkById.get('my-sink')?.taintedArgs).toEqual([0, 1]);
  });

  it('ignorePaths は置換される（組み込み既定を捨てる）', async () => {
    const config = await resolveConfig({ root: fixture('full') });
    expect(config.rules.ignorePaths).toEqual(['**/node_modules/**', '**/*.generated.ts']);
  });

  it('analysis / output は浅いマージになる', async () => {
    const config = await resolveConfig({ root: fixture('full') });
    expect(config.analysis).toEqual({ maxCallDepth: 5, maxIterations: 42, dedupe: false });
    expect(config.output).toEqual({ format: 'sarif', output: 'reports/out.sarif', failOn: 'warning' });
  });

  it('同じ id の規則は後勝ちで上書きされ、件数は増えない', async () => {
    const config = await resolveConfig({ root: fixture('override') });
    expect(config.rules.sinks.length).toBe(BUILTIN_SINKS.length);
    expect(config.rules.sinks[0]?.id).toBe('sql-query');
    expect(config.rules.sinks[0]?.severity).toBe('note');
    expect(config.rules.sinks[0]?.kinds).toEqual(['nosql']);
  });

  it('overrides は設定ファイルより強い', async () => {
    const config = await resolveConfig({
      root: fixture('full'),
      overrides: { format: 'json', failOn: 'none', maxCallDepth: 1, output: 'cli.json', kinds: ['sql'] },
    });
    expect(config.output).toEqual({ format: 'json', output: 'cli.json', failOn: 'none' });
    expect(config.analysis.maxCallDepth).toBe(1);
    expect(config.analysis.kinds).toEqual(['sql']);
    expect(config.analysis.maxIterations).toBe(42);
  });
});

describe('resolveConfig: エラーと警告', () => {
  it('未知キーは onWarning に流れて解析は続行する', async () => {
    const onWarning = vi.fn();
    const config = await resolveConfig({ root: fixture('minimal'), onWarning });
    expect(config.output.format).toBe('markdown');
    expect(onWarning).toHaveBeenCalledWith(expect.stringContaining('verbosity'), 'output.verbosity');
  });

  it('YAML の構文エラーはファイルパスと行番号付きの ConfigError', async () => {
    const error = await configErrorOf(() => resolveConfig({ root: fixture('broken') }));
    expect(error.message).toContain('区切り');
    expect(error.path.endsWith('.shirokuma.yml:5')).toBe(true);
    expect(error.path.startsWith(fixture('broken'))).toBe(true);
  });

  it('型エラーは rules.sinks[0].severity を指す ConfigError', async () => {
    const error = await configErrorOf(() => resolveConfig({ root: fixture('invalid') }));
    expect(error.path).toBe('rules.sinks[0].severity');
  });
});

describe('ruleSetFromDocument', () => {
  it('組み込みへ追記したルールセットを返す', () => {
    const rules = ruleSetFromDocument({ rules: { sources: [{ id: 'extra', member: 'req.x', kinds: ['sql'] }], sanitizers: [], sinks: [], propagators: [] } });
    expect(rules.sources.length).toBe(BUILTIN_SOURCES.length + 1);
    expect(rules.ignorePaths).toEqual(DEFAULT_IGNORE_PATHS);
  });
});
