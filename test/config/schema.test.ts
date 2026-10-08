/**
 * YAML サブセットパーサとパス付き検証器の挙動を固定する。
 *
 * パーサは依存パッケージを使わない自前実装であり、設定ファイルの記法を
 * 「どこまで受け付けるか」「どこで ConfigError になるか」を 1 件ずつ確認する。
 */
import { describe, expect, it, vi } from 'vitest';
import { ConfigError } from '../../src/config/contract.js';
import {
  expectEnum,
  expectStringArray,
  isRecord,
  normalizeAnalysisConfig,
  normalizeOutputConfig,
  normalizeSinkSpec,
  normalizeSourceSpec,
  parseYaml,
  validateDocument,
} from '../../src/config/schema.js';

/** YAML の構文エラーを検証するヘルパー。 */
function parseError(text: string): ConfigError {
  try {
    parseYaml(text, 'test.yml');
  } catch (error) {
    if (error instanceof ConfigError) return error;
    throw error;
  }
  throw new Error('ConfigError が投げられませんでした');
}

/** ドキュメント検証エラーを検証するヘルパー。 */
function validationError(doc: unknown): ConfigError {
  try {
    validateDocument(doc);
  } catch (error) {
    if (error instanceof ConfigError) return error;
    throw error;
  }
  throw new Error('ConfigError が投げられませんでした');
}

describe('parseYaml: マップとスカラー', () => {
  it('トップレベルのマップを解析する', () => {
    expect(parseYaml('format: sarif\nfailOn: error\n')).toEqual({ format: 'sarif', failOn: 'error' });
  });

  it('スカラーの型を YAML 1.2 core スキーマで解決する', () => {
    const parsed = parseYaml('a: true\nb: false\nc: null\nd: ~\ne: 10\nf: 1.5\ng: yes\nh: text\n');
    expect(parsed).toEqual({ a: true, b: false, c: null, d: null, e: 10, f: 1.5, g: 'yes', h: 'text' });
  });

  it('ネストしたマップを解析する', () => {
    const parsed = parseYaml('analysis:\n  maxCallDepth: 4\n  dedupe: true\noutput:\n  format: json\n');
    expect(parsed).toEqual({ analysis: { maxCallDepth: 4, dedupe: true }, output: { format: 'json' } });
  });

  it('空の値は null になる', () => {
    expect(parseYaml('a:\nb: 1\n')).toEqual({ a: null, b: 1 });
  });

  it('空のドキュメントは空のマップになる', () => {
    expect(parseYaml('')).toEqual({});
    expect(parseYaml('# コメントだけ\n\n')).toEqual({});
  });

  it('ドキュメント区切りを無視する', () => {
    expect(parseYaml('---\na: 1\n...\n')).toEqual({ a: 1 });
  });
});

describe('parseYaml: シーケンス', () => {
  it('スカラーのシーケンスを解析する', () => {
    expect(parseYaml('kinds:\n  - sql\n  - html\n')).toEqual({ kinds: ['sql', 'html'] });
  });

  it('キーと同じインデントのシーケンスを解析する', () => {
    expect(parseYaml('kinds:\n- sql\n- html\n')).toEqual({ kinds: ['sql', 'html'] });
  });

  it('マップのシーケンスを解析する（設定の中心的な形）', () => {
    const text = ['sinks:', '  - id: sql-query', '    kinds: [sql]', '    severity: error', '  - id: xss', '    severity: warning', ''].join('\n');
    expect(parseYaml(text)).toEqual({
      sinks: [
        { id: 'sql-query', kinds: ['sql'], severity: 'error' },
        { id: 'xss', severity: 'warning' },
      ],
    });
  });

  it('マップのシーケンスがネストしたマップを伴う', () => {
    const text = ['sources:', '  - id: s1', '    withinFunctions:', '      - handler', '      - other', '  - id: s2', ''].join('\n');
    expect(parseYaml(text)).toEqual({
      sources: [
        { id: 's1', withinFunctions: ['handler', 'other'] },
        { id: 's2' },
      ],
    });
  });

  it('ネストしたシーケンスを解析する', () => {
    expect(parseYaml('matrix:\n  - - a\n    - b\n  - - c\n')).toEqual({ matrix: [['a', 'b'], ['c']] });
  });

  it('空のシーケンス要素は null になる', () => {
    expect(parseYaml('list:\n  -\n  - a\n')).toEqual({ list: [null, 'a'] });
  });
});

describe('parseYaml: フローコレクション', () => {
  it('フローシーケンスを解析する', () => {
    expect(parseYaml('kinds: [sql, html, command]\n')).toEqual({ kinds: ['sql', 'html', 'command'] });
  });

  it('フローマップを解析する', () => {
    expect(parseYaml('output: { format: json, failOn: none }\n')).toEqual({ output: { format: 'json', failOn: 'none' } });
  });

  it('空のフローコレクションを解析する', () => {
    expect(parseYaml('a: []\nb: {}\n')).toEqual({ a: [], b: {} });
  });

  it('フローコレクション内のクォート文字列を解析する', () => {
    expect(parseYaml('cwe: ["CWE-89", \'CWE-79\']\n')).toEqual({ cwe: ['CWE-89', 'CWE-79'] });
  });
});

describe('parseYaml: クォート・コメント・ブロックスカラー', () => {
  it('シングルクォートのエスケープ（\'\'）を解析する', () => {
    expect(parseYaml("message: 'it''s ok'\n")).toEqual({ message: "it's ok" });
  });

  it('ダブルクォートのエスケープを解析する', () => {
    expect(parseYaml('message: "a\\nb\\tc\\u3042"\n')).toEqual({ message: 'a\nb\tc\u3042' });
  });

  it('行末コメントと行全体コメントを除去する', () => {
    expect(parseYaml('# 先頭\nformat: sarif # 出力形式\n')).toEqual({ format: 'sarif' });
  });

  it('クォート内の `#` はコメントとして扱わない', () => {
    expect(parseYaml('message: "a # b"\n')).toEqual({ message: 'a # b' });
  });

  it('URL 内の `:` をキー区切りと誤認しない', () => {
    expect(parseYaml('uri: http://example.com/a\n')).toEqual({ uri: 'http://example.com/a' });
  });

  it('ブロックスカラー（| クリップ）を解析する', () => {
    const parsed = parseYaml('advice: |\n  1 行目\n  2 行目\noutput:\n  format: json\n');
    expect(parsed).toEqual({ advice: '1 行目\n2 行目\n', output: { format: 'json' } });
  });

  it('ブロックスカラー（|- ストリップ）を解析する', () => {
    expect(parseYaml('advice: |-\n  a\n  b\n')).toEqual({ advice: 'a\nb' });
  });

  it('ブロックスカラー（> 折り返し）を解析する', () => {
    expect(parseYaml('advice: >\n  a\n  b\n')).toEqual({ advice: 'a b\n' });
  });
});

describe('parseYaml: 構文エラー', () => {
  it('キーが重複したら ConfigError', () => {
    const error = parseError('a: 1\na: 2\n');
    expect(error.path).toBe('test.yml:2');
    expect(error.message).toContain('重複');
  });

  it('タブインデントは ConfigError', () => {
    const error = parseError('a:\n\tb: 1\n');
    expect(error.message).toContain('タブ');
  });

  it('区切り `:` が無い行は ConfigError', () => {
    const error = parseError('a: 1\nthis line has no colon\n');
    expect(error.path).toBe('test.yml:2');
    expect(error.message).toContain('区切り');
  });

  it('閉じられていないクォートは ConfigError', () => {
    expect(parseError("a: 'unterminated\n").message).toContain('閉じられていません');
  });

  it('インデントが深すぎる場合は ConfigError', () => {
    expect(parseError('a: 1\n    b: 2\n').message).toContain('インデント');
  });

  it('マップの中のシーケンス要素は ConfigError', () => {
    expect(parseError('a: 1\n- b\n').message).toContain('シーケンス');
  });

  it('フローコレクションの閉じ忘れは ConfigError', () => {
    expect(parseError('a: [1, 2\n').message.length).toBeGreaterThan(0);
  });
});

describe('validateDocument', () => {
  it('空のドキュメントは空のルール定義になる', () => {
    expect(validateDocument(null)).toEqual({ rules: { sources: [], sanitizers: [], sinks: [], propagators: [] } });
  });

  it('フル設定を型付きで返す', () => {
    const doc = validateDocument({
      version: 1,
      rules: {
        sources: [{ id: 's', member: 'req.query', kinds: ['sql'] }],
        sanitizers: [{ id: 'z', call: 'escapeAll', kinds: ['html'] }],
        sinks: [{ id: 'k', call: 'run', kinds: ['sql'], severity: 'error', message: '到達' }],
        propagators: [{ call: 'passthrough' }],
        ignorePaths: ['**/vendor/**'],
      },
      analysis: { maxCallDepth: 2, maxIterations: 10, dedupe: false, kinds: ['sql'] },
      output: { format: 'json', output: 'out.json', failOn: 'note' },
    });
    expect(doc.schemaVersion).toBe(1);
    expect(doc.rules.sources).toEqual([{ id: 's', kinds: ['sql'], member: 'req.query' }]);
    expect(doc.rules.sinks[0]?.severity).toBe('error');
    expect(doc.rules.ignorePaths).toEqual(['**/vendor/**']);
    expect(doc.analysis).toEqual({ maxCallDepth: 2, maxIterations: 10, dedupe: false, kinds: ['sql'] });
    expect(doc.output).toEqual({ format: 'json', output: 'out.json', failOn: 'note' });
  });

  it('サニタイザの validation 既定値は none', () => {
    const doc = validateDocument({ rules: { sanitizers: [{ id: 'z', call: 'f', kinds: [] }] } });
    expect(doc.rules.sanitizers[0]?.validation).toBe('none');
    expect(doc.rules.sanitizers[0]?.kinds).toEqual([]);
  });

  it('未知のトップレベルキーは警告して続行する', () => {
    const onWarning = vi.fn();
    const doc = validateDocument({ unknownKey: 1, rules: {} }, onWarning);
    expect(doc.rules.sources).toEqual([]);
    expect(onWarning).toHaveBeenCalledWith(expect.stringContaining('unknownKey'), 'unknownKey');
  });

  it('未知のネストキーはパス付きで警告する', () => {
    const onWarning = vi.fn();
    validateDocument({ rules: { sinks: [{ id: 'k', call: 'run', kinds: ['sql'], severity: 'error', message: 'm', sevrity: 'error' }] } }, onWarning);
    expect(onWarning).toHaveBeenCalledWith(expect.stringContaining('sevrity'), 'rules.sinks[0].sevrity');
  });

  it('severity の欠落は rules.sinks[0].severity を指す ConfigError', () => {
    const error = validationError({ rules: { sinks: [{ id: 'k', call: 'run', kinds: ['sql'], message: 'm' }] } });
    expect(error.path).toBe('rules.sinks[0].severity');
    expect(error.message).toContain('severity');
  });

  it('severity の値が不正なら ConfigError', () => {
    const error = validationError({ rules: { sinks: [{ id: 'k', call: 'run', kinds: ['sql'], severity: 'fatal', message: 'm' }] } });
    expect(error.path).toBe('rules.sinks[0].severity');
    expect(error.message).toContain('fatal');
  });

  it('sinks[].kinds が空なら ConfigError', () => {
    const error = validationError({ rules: { sinks: [{ id: 'k', call: 'run', kinds: [], severity: 'error', message: 'm' }] } });
    expect(error.path).toBe('rules.sinks[0].kinds');
  });

  it('taintedArgs が負の数なら ConfigError', () => {
    const error = validationError({ rules: { sinks: [{ id: 'k', call: 'run', kinds: ['sql'], severity: 'error', message: 'm', taintedArgs: [-1] }] } });
    expect(error.path).toBe('rules.sinks[0].taintedArgs[0]');
  });

  it('taintedArgs が配列でなければ ConfigError', () => {
    const error = validationError({ rules: { sinks: [{ id: 'k', call: 'run', kinds: ['sql'], severity: 'error', message: 'm', taintedArgs: 0 }] } });
    expect(error.path).toBe('rules.sinks[0].taintedArgs');
  });

  it('照合条件が無いソースは ConfigError', () => {
    const error = validationError({ rules: { sources: [{ id: 's', kinds: ['sql'] }] } });
    expect(error.path).toBe('rules.sources[0]');
    expect(error.message).toContain('member');
  });

  it('member に空白や括弧は使えない', () => {
    const error = validationError({ rules: { sources: [{ id: 's', member: 'db.query()', kinds: ['sql'] }] } });
    expect(error.path).toBe('rules.sources[0].member');
  });

  it('call は単純な関数名でなければならない', () => {
    const error = validationError({ rules: { sinks: [{ id: 'k', call: 'a.b', kinds: ['sql'], severity: 'error', message: 'm' }] } });
    expect(error.path).toBe('rules.sinks[0].call');
  });

  it('validation の値が不正なら ConfigError', () => {
    const error = validationError({ rules: { sanitizers: [{ id: 'z', call: 'f', kinds: ['html'], validation: 'always' }] } });
    expect(error.path).toBe('rules.sanitizers[0].validation');
  });

  it('version が 1 以外なら ConfigError', () => {
    const error = validationError({ version: 2 });
    expect(error.path).toBe('version');
    expect(error.message).toContain('1 のみ');
  });

  it('schemaVersion: 1 も受け付ける', () => {
    expect(validateDocument({ schemaVersion: 1 }).schemaVersion).toBe(1);
  });

  it('トップレベルの ignorePaths は rules.ignorePaths の別名', () => {
    const doc = validateDocument({ ignorePaths: ['**/a/**'] });
    expect(doc.rules.ignorePaths).toEqual(['**/a/**']);
  });

  it('rules.ignorePaths の空配列は「除外なし」として保持する', () => {
    expect(validateDocument({ rules: { ignorePaths: [] } }).rules.ignorePaths).toEqual([]);
  });

  it('ルートがマップでなければ ConfigError', () => {
    expect(validationError([1, 2]).path).toBe('config');
  });

  it('withinFunctions と description を保持する', () => {
    const doc = validateDocument({ rules: { sources: [{ id: 's', member: 'req.query', kinds: ['sql'], withinFunctions: ['handler'], description: '説明' }] } });
    expect(doc.rules.sources[0]).toEqual({ id: 's', kinds: ['sql'], member: 'req.query', withinFunctions: ['handler'], description: '説明' });
  });

  it('output に format が無ければ ConfigError', () => {
    expect(validationError({ output: { failOn: 'error' } }).path).toBe('output.format');
  });

  it('analysis は部分指定でも既定値で補完される', () => {
    expect(validateDocument({ analysis: { dedupe: false } }).analysis).toEqual({ maxCallDepth: 3, maxIterations: 200, dedupe: false });
  });

  it('analysis の maxIterations が 0 以下なら ConfigError', () => {
    expect(validationError({ analysis: { maxIterations: 0 } }).path).toBe('analysis.maxIterations');
  });
});

describe('正規化ヘルパー', () => {
  it('isRecord は配列と null を弾く', () => {
    expect(isRecord({})).toBe(true);
    expect(isRecord([])).toBe(false);
    expect(isRecord(null)).toBe(false);
    expect(isRecord('x')).toBe(false);
  });

  it('expectStringArray は空配列の可否を制御する', () => {
    expect(expectStringArray(['a'], 'p', false)).toEqual(['a']);
    expect(() => expectStringArray([], 'p', false)).toThrowError(ConfigError);
    expect(expectStringArray([], 'p', true)).toEqual([]);
    expect(() => expectStringArray(['a', 1], 'p', true)).toThrowError(/p\[1\]/);
  });

  it('expectEnum は候補外の値を拒否する', () => {
    expect(expectEnum('json', ['json', 'sarif'] as const, 'output.format')).toBe('json');
    expect(() => expectEnum('xml', ['json', 'sarif'] as const, 'output.format')).toThrowError(/output\.format/);
  });

  it('normalizeSourceSpec は検証済みのソースを返す', () => {
    expect(normalizeSourceSpec({ id: 's', kinds: ['sql'], member: 'db.query' }, 'rules.sources[0]')).toEqual({
      id: 's',
      kinds: ['sql'],
      member: 'db.query',
    });
  });

  it('normalizeSinkSpec は taintedArgs と cwe を検証する', () => {
    const sink = normalizeSinkSpec(
      { id: 'k', call: 'run', kinds: ['sql'], severity: 'note', message: 'm', taintedArgs: [0, 2], cwe: ['CWE-89'] },
      'rules.sinks[0]',
    );
    expect(sink.taintedArgs).toEqual([0, 2]);
    expect(sink.cwe).toEqual(['CWE-89']);
  });

  it('normalizeAnalysisConfig / normalizeOutputConfig は既定値を補う', () => {
    expect(normalizeAnalysisConfig({}, 'analysis')).toEqual({ maxCallDepth: 3, maxIterations: 200 });
    expect(normalizeOutputConfig({ format: 'markdown' }, 'output')).toEqual({ format: 'markdown' });
  });
});
