/**
 * 共通ユーティリティの実装。
 *
 * ここにある関数は解析とレポートの両方から呼ばれるため、
 * 入出力を決定的に保つ（同じ入力なら常に同じ出力）ことを最優先にしている。
 */
import { createHash } from 'node:crypto';
import path from 'node:path';
import type { Severity } from '../types.js';

/** 文字列の SHA-256 を `hexLength` 文字で返す。 */
export function sha256(text: string, hexLength = 16): string {
  return createHash('sha256').update(text, 'utf8').digest('hex').slice(0, hexLength);
}

/** 検出 ID を組み立てる。同一の指摘が再実行でも同じ ID になるようにする。 */
export function makeFindingId(ruleId: string, relativePath: string, line: number, column: number): string {
  return `${ruleId}:${relativePath}:${line}:${column}`;
}

/** 重要度の序列。数値が大きいほど重大。 */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> = Object.freeze({
  note: 0,
  warning: 1,
  error: 2,
});

/** `value` が `threshold` 以上に重大なら true。`threshold` が `'none'` なら常に false。 */
export function meetsSeverity(value: Severity, threshold: Severity | 'none'): boolean {
  if (threshold === 'none') {
    return false;
  }
  return SEVERITY_RANK[value] >= SEVERITY_RANK[threshold];
}

/** バックスラッシュを `/` に統一し、連続スラッシュと末尾スラッシュを畳む。 */
export function toPosixPath(value: string): string {
  let result = value.replace(/\\/g, '/');
  result = result.replace(/\/{2,}/g, '/');
  if (result.length > 1 && result.endsWith('/')) {
    result = result.slice(0, -1);
  }
  return result;
}

const GLOB_SPECIAL = new Set(['.', '+', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\']);

/**
 * glob 風パターンを RegExp へ変換する。
 *
 * 対応する構文:
 * - `**`  : 任意のパス（ディレクトリ区切りを含む）。`**\/` は「0 個以上のディレクトリ」。
 * - `*`   : ディレクトリ区切りを含まない任意の文字列。
 * - `?`   : 区切り以外の任意の 1 文字。
 * - それ以外の文字はエスケープしてリテラル扱い。
 *
 * 例: `**\/*.test.ts` は `a.test.ts` にも `src\/a.test.ts` にも一致する。
 */
export function globToRegExp(pattern: string): RegExp {
  const normalized = toPosixPath(pattern);
  let body = '';

  for (let index = 0; index < normalized.length; index += 1) {
    const char = normalized[index];
    if (char === undefined) {
      break;
    }

    if (char === '*') {
      const isDouble = normalized[index + 1] === '*';
      if (isDouble) {
        const slashAfter = normalized[index + 2] === '/';
        if (slashAfter) {
          // `**/` は 0 個以上のディレクトリを表す。
          body += '(?:[^/]*/)*';
          index += 2;
        } else {
          body += '.*';
          index += 1;
        }
      } else {
        body += '[^/]*';
      }
      continue;
    }

    if (char === '?') {
      body += '[^/]';
      continue;
    }

    body += GLOB_SPECIAL.has(char) ? `\\${char}` : char;
  }

  return new RegExp(`^${body}$`);
}

/** パターン一致結果のメモ。同じパターンを何度も変換しないようにする。 */
const globCache = new Map<string, RegExp>();

function globFor(pattern: string): RegExp {
  const cached = globCache.get(pattern);
  if (cached !== undefined) {
    return cached;
  }
  const compiled = globToRegExp(pattern);
  globCache.set(pattern, compiled);
  return compiled;
}

/**
 * glob の一致判定。
 *
 * `.gitignore` と同じ感覚で使えるよう、ディレクトリを指すパターンは
 * 配下のすべてに一致させる。例: `node_modules` は `node_modules/a/b.js` にも一致する。
 */
export function matchesAnyGlob(relativePath: string, patterns: readonly string[]): boolean {
  const target = toPosixPath(relativePath).replace(/^\.\//, '');
  return patterns.some((pattern) => {
    const normalized = toPosixPath(pattern).replace(/^\.\//, '');
    if (globFor(normalized).test(target)) {
      return true;
    }
    // ディレクトリ指定（`dist`）や `dist/` は配下全体に一致させる。
    if (!normalized.includes('*') && !normalized.includes('?')) {
      const prefix = normalized.endsWith('/') ? normalized : `${normalized}/`;
      return target.startsWith(prefix);
    }
    return false;
  });
}

/** 連続する空白・改行・タブを 1 つのスペースへ畳み、前後の空白を落とす。 */
export function collapseWhitespace(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/** `maxLength` 文字で切り詰め、省略した場合は末尾に `…` を付ける。 */
export function truncate(text: string, maxLength: number): string {
  if (maxLength <= 0) {
    return '';
  }
  if (text.length <= maxLength) {
    return text;
  }
  return `${text.slice(0, maxLength)}…`;
}

/** 決定的な順序でソートする比較関数を作る。 */
export function compareBy<T>(...selectors: readonly ((item: T) => string | number)[]): (a: T, b: T) => number {
  return (a: T, b: T): number => {
    for (const selector of selectors) {
      const left = selector(a);
      const right = selector(b);
      if (left === right) {
        continue;
      }
      if (typeof left === 'number' && typeof right === 'number') {
        return left - right;
      }
      return String(left) < String(right) ? -1 : 1;
    }
    return 0;
  };
}

/** TypeScript Compiler API の 0-based 列を 1-based へ変換する。 */
export function toOneBasedColumn(zeroBased: number): number {
  return zeroBased + 1;
}

/** プロジェクトルートからの相対パスを POSIX 区切りで返す。 */
export function relativeToRoot(root: string, absolutePath: string): string {
  return toPosixPath(path.posix.relative(toPosixPath(root), toPosixPath(absolutePath)));
}
