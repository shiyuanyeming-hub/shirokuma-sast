/**
 * 解析対象ファイルの探索。
 *
 * `node_modules` や `dist` などの生成物を既定で除外し、
 * 拡張子と言語でフィルタする。探索順は決定的（辞書順）で、
 * 同じリポジトリから常に同じ順序の結果を返す。
 */
import { readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import type { Diagnostic } from './types.js';
import { matchesAnyGlob, toPosixPath } from './util/impl.js';

/** 既定で解析する拡張子。 */
export const DEFAULT_EXTENSIONS: readonly string[] = ['.ts', '.tsx', '.mts', '.cts', '.js', '.jsx', '.mjs', '.cjs'];

/** 既定で除外するパス。生成物・依存・テスト用フィクスチャを含む。 */
export const DEFAULT_EXCLUDE: readonly string[] = [
  'node_modules',
  'dist',
  'build',
  'out',
  'coverage',
  '.git',
  '.next',
  '.nuxt',
  '.svelte-kit',
  'vendor',
  '.venv',
  'venv',
  '**/*.d.ts',
  '**/*.min.js',
  '**/*.bundle.js',
];

/** 宣言ファイル（`.d.ts`）は型情報のみなので既定で除外する。 */
export function isDeclarationFile(filePath: string): boolean {
  return filePath.endsWith('.d.ts') || filePath.endsWith('.d.mts') || filePath.endsWith('.d.cts');
}

export interface DiscoverOptions {
  /** 探索ルート（絶対パスまたは相対パス）。 */
  readonly root: string;
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
  readonly extensions?: readonly string[];
  /** 単一ファイルを直接指定する場合。指定するとディレクトリ探索を行わない。 */
  readonly files?: readonly string[];
}

export interface DiscoverResult {
  /** 解析対象の絶対パス（辞書順）。 */
  readonly files: readonly string[];
  readonly diagnostics: readonly Diagnostic[];
}

/**
 * 解析対象のファイル一覧を返す。
 *
 * - シンボリックリンクは辿らない（循環と無限再帰を避けるため）。
 * - 読み取り権限の無いディレクトリは診断を残して続行する。
 */
export async function discoverFiles(options: DiscoverOptions): Promise<DiscoverResult> {
  const root = path.resolve(options.root);
  const diagnostics: Diagnostic[] = [];
  const extensions = options.extensions ?? DEFAULT_EXTENSIONS;
  const exclude = [...DEFAULT_EXCLUDE, ...(options.exclude ?? [])];

  if (options.files !== undefined && options.files.length > 0) {
    const resolved = options.files.map((file) => path.resolve(file)).sort();
    return { files: resolved, diagnostics };
  }

  let rootStat;
  try {
    rootStat = await stat(root);
  } catch (error) {
    diagnostics.push({
      level: 'error',
      message: `解析ルートを開けませんでした: ${error instanceof Error ? error.message : String(error)}`,
    });
    return { files: [], diagnostics };
  }

  if (rootStat.isFile()) {
    return { files: [root], diagnostics };
  }

  const collected: string[] = [];

  const walk = async (directory: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      diagnostics.push({
        level: 'warning',
        message: `ディレクトリを読めませんでした: ${error instanceof Error ? error.message : String(error)}`,
        file: directory,
      });
      return;
    }

    // 決定的な順序にするため名前で並べる。
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    for (const entry of entries) {
      const absolute = path.join(directory, entry.name);
      const relativePath = toPosixPath(path.relative(root, absolute));

      if (entry.isSymbolicLink()) {
        continue;
      }

      if (entry.isDirectory()) {
        if (matchesAnyGlob(relativePath, exclude)) {
          continue;
        }
        await walk(absolute);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }
      if (matchesAnyGlob(relativePath, exclude)) {
        continue;
      }
      if (isDeclarationFile(absolute)) {
        continue;
      }
      if (!extensions.some((extension) => absolute.endsWith(extension))) {
        continue;
      }
      if (options.include !== undefined && options.include.length > 0 && !matchesAnyGlob(relativePath, options.include)) {
        continue;
      }
      collected.push(absolute);
    }
  };

  await walk(root);
  collected.sort((a, b) => (toPosixPath(a) < toPosixPath(b) ? -1 : toPosixPath(a) > toPosixPath(b) ? 1 : 0));
  return { files: collected, diagnostics };
}
