import { describe, expect, it } from 'vitest';
import {
  collapseWhitespace,
  compareBy,
  globToRegExp,
  makeFindingId,
  matchesAnyGlob,
  meetsSeverity,
  relativeToRoot,
  sha256,
  toOneBasedColumn,
  toPosixPath,
  truncate,
} from '../../src/util/impl.js';

describe('sha256', () => {
  it('既定で 16 文字の 16 進を返す', () => {
    expect(sha256('hello')).toHaveLength(16);
    expect(sha256('hello')).toMatch(/^[0-9a-f]+$/);
  });

  it('同じ入力に対して決定的である', () => {
    expect(sha256('abc', 32)).toBe(sha256('abc', 32));
  });

  it('異なる入力では異なる値を返す', () => {
    expect(sha256('abc')).not.toBe(sha256('abd'));
  });

  it('長さを指定できる', () => {
    expect(sha256('abc', 8)).toHaveLength(8);
  });
});

describe('makeFindingId', () => {
  it('ruleId と位置から安定 ID を作る', () => {
    expect(makeFindingId('sql-injection', 'src/app.ts', 12, 5)).toBe('sql-injection:src/app.ts:12:5');
  });
});

describe('meetsSeverity', () => {
  it('同値以上なら true', () => {
    expect(meetsSeverity('error', 'error')).toBe(true);
    expect(meetsSeverity('error', 'warning')).toBe(true);
    expect(meetsSeverity('warning', 'error')).toBe(false);
    expect(meetsSeverity('note', 'warning')).toBe(false);
  });

  it("'none' は常に false（CI ゲートを無効化する）", () => {
    expect(meetsSeverity('error', 'none')).toBe(false);
  });
});

describe('toPosixPath', () => {
  it('バックスラッシュをスラッシュへ変換する', () => {
    expect(toPosixPath('src\\a\\b.ts')).toBe('src/a/b.ts');
  });

  it('連続スラッシュを畳む', () => {
    expect(toPosixPath('src//a///b.ts')).toBe('src/a/b.ts');
  });

  it('末尾スラッシュを落とす（ルートは保持）', () => {
    expect(toPosixPath('src/a/')).toBe('src/a');
    expect(toPosixPath('/')).toBe('/');
  });
});

describe('globToRegExp / matchesAnyGlob', () => {
  it('**/ は 0 個以上のディレクトリに一致する', () => {
    expect(matchesAnyGlob('a.test.ts', ['**/*.test.ts'])).toBe(true);
    expect(matchesAnyGlob('src/deep/a.test.ts', ['**/*.test.ts'])).toBe(true);
    expect(matchesAnyGlob('src/a.ts', ['**/*.test.ts'])).toBe(false);
  });

  it('* はディレクトリ区切りをまたがない', () => {
    expect(matchesAnyGlob('src/a.ts', ['src/*.ts'])).toBe(true);
    expect(matchesAnyGlob('src/deep/a.ts', ['src/*.ts'])).toBe(false);
  });

  it('ディレクトリ指定は配下全体に一致する', () => {
    expect(matchesAnyGlob('node_modules/pkg/index.js', ['node_modules'])).toBe(true);
    expect(matchesAnyGlob('dist/a/b.js', ['dist'])).toBe(true);
    expect(matchesAnyGlob('src/node_modules.ts', ['node_modules'])).toBe(false);
  });

  it('? は 1 文字に一致する', () => {
    expect(matchesAnyGlob('a1.ts', ['a?.ts'])).toBe(true);
    expect(matchesAnyGlob('a12.ts', ['a?.ts'])).toBe(false);
  });

  it('正規表現の特殊文字をリテラル扱いする', () => {
    expect(matchesAnyGlob('a+b.ts', ['a+b.ts'])).toBe(true);
    expect(matchesAnyGlob('aab.ts', ['a+b.ts'])).toBe(false);
    expect(globToRegExp('a.b').test('axb')).toBe(false);
  });

  it('./ 接頭辞を無視する', () => {
    expect(matchesAnyGlob('./src/a.ts', ['./src/*.ts'])).toBe(true);
    expect(matchesAnyGlob('src/a.ts', ['./src/*.ts'])).toBe(true);
  });

  it('パターンが空なら一致しない', () => {
    expect(matchesAnyGlob('a.ts', [])).toBe(false);
  });
});

describe('collapseWhitespace / truncate', () => {
  it('空白と改行を 1 スペースへ畳む', () => {
    expect(collapseWhitespace('  const  a\n\t= 1;  ')).toBe('const a = 1;');
  });

  it('長い文字列を … 付きで切り詰める', () => {
    expect(truncate('abcdef', 3)).toBe('abc…');
    expect(truncate('abc', 3)).toBe('abc');
    expect(truncate('abc', 0)).toBe('');
  });
});

describe('compareBy', () => {
  it('複数キーで決定的に並べる', () => {
    const items = [
      { file: 'b.ts', line: 1 },
      { file: 'a.ts', line: 9 },
      { file: 'a.ts', line: 2 },
    ];
    const sorted = [...items].sort(
      compareBy<{ file: string; line: number }>(
        (i: { file: string; line: number }) => i.file,
        (i: { file: string; line: number }) => i.line,
      ),
    );
    expect(sorted).toEqual([
      { file: 'a.ts', line: 2 },
      { file: 'a.ts', line: 9 },
      { file: 'b.ts', line: 1 },
    ]);
  });

  it('等しい要素では 0 を返す', () => {
    const cmp = compareBy<{ v: number }>((i: { v: number }) => i.v);
    expect(cmp({ v: 1 }, { v: 1 })).toBe(0);
  });
});

describe('relativeToRoot / toOneBasedColumn', () => {
  it('ルートからの相対を POSIX 区切りで返す', () => {
    expect(relativeToRoot('/a/b', '/a/b/c/d.ts')).toBe('c/d.ts');
    expect(relativeToRoot('/a/b', '/a/b/c/d.ts').includes('\\')).toBe(false);
  });

  it('0-based 列を 1-based へ変換する', () => {
    expect(toOneBasedColumn(0)).toBe(1);
    expect(toOneBasedColumn(41)).toBe(42);
  });
});
