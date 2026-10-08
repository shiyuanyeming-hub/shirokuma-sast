/**
 * 設定の解決 — 組み込み既定 → 設定ファイル → CLI 上書き、の順にマージする。
 *
 * ## 優先順位（上が強い）
 * 1. `overrides`（CLI フラグ相当）
 * 2. `--config` で指定されたファイル
 * 3. 探索で見つかった `.shirokuma.yml` / `.shirokuma.yaml`（`CONFIG_FILE_CANDIDATES` の順）
 * 4. 組み込み既定（`src/rules/builtin.ts`）
 *
 * ## マージ規則
 * - `rules.sources` / `sanitizers` / `sinks` / `propagators` は **追記**（同じ `id` は後勝ち。
 *   位置は最初の宣言のまま保ち、レポートの ruleId 順を安定させる）。
 * - `ignorePaths` は **置換**（明示指定があれば組み込み既定を捨てる。空配列なら除外なし）。
 * - `analysis` / `output` は浅いマージ。
 *
 * ## エラー方針
 * 構文エラー・型不一致は `ConfigError`（`path` に `rules.sinks[2].severity` のような位置）を投げ、
 * 黙って既定値へ落とさない。未知のキーは警告として `onWarning` へ流し、解析は続行する。
 */
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import type { OutputConfig, PatternSpec, ResolvedRuleSet, SanitizerSpec, SinkSpec, SourceSpec, TaintConfig } from '../types.js';
import {
  BUILTIN_PROPAGATORS,
  BUILTIN_SANITIZERS,
  BUILTIN_SINKS,
  BUILTIN_SOURCES,
  DEFAULT_ANALYSIS,
  DEFAULT_IGNORE_PATHS,
  DEFAULT_OUTPUT,
} from '../rules/builtin.js';
import { ConfigError } from './contract.js';
import type { ResolveConfigOptions } from './contract.js';
import {
  normalizePropagator,
  normalizeRuleList,
  normalizeSanitizerSpec,
  normalizeSinkSpec,
  normalizeSourceSpec,
  parseYaml,
  validateDocument,
} from './schema.js';
import type { NormalizeOptions, ValidatedDocument, WarningSink } from './schema.js';

/**
 * 設定ファイルの探索順（`root` からの相対パス）。
 *
 * 先に見つかったものだけを使う（複数ファイルのマージはしない）。
 */
export const CONFIG_FILE_CANDIDATES: readonly string[] = ['.shirokuma.yml', '.shirokuma.yaml'];

/** 設定ファイルとして解釈できるタグ語彙（サニタイザの `kinds: []` 展開に使う）。 */
const TAG_VOCABULARY: readonly string[] = ['code', 'command', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url'];

/** 設定ファイルが無いときの空ドキュメント。 */
const EMPTY_DOCUMENT: ValidatedDocument = { rules: { sources: [], sanitizers: [], sinks: [], propagators: [] } };

/** ファイルが存在するか（通常ファイルのみ）。 */
async function isFile(candidate: string): Promise<boolean> {
  try {
    const info = await stat(candidate);
    return info.isFile();
  } catch {
    return false;
  }
}

/** 使用する設定ファイルを決定する。見つからなければ undefined（＝組み込み既定のみ）。 */
async function findConfigFile(options: ResolveConfigOptions): Promise<string | undefined> {
  if (options.configPath !== undefined && options.configPath !== '') {
    const resolved = path.resolve(options.root, options.configPath);
    if (!(await isFile(resolved))) {
      throw new ConfigError(
        `設定ファイルが見つかりません: ${options.configPath}`,
        options.configPath,
        '--config のパスを確認するか、--no-config で組み込み既定を使ってください',
      );
    }
    return resolved;
  }
  if (options.builtinOnly === true) return undefined;
  for (const candidate of CONFIG_FILE_CANDIDATES) {
    const resolved = path.join(options.root, candidate);
    if (await isFile(resolved)) return resolved;
  }
  return undefined;
}

/** 設定ファイルを読み込み、検証済みドキュメントを返す。 */
async function readConfigDocument(file: string, onWarning: WarningSink | undefined): Promise<ValidatedDocument> {
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    throw new ConfigError(`設定ファイルを読み込めませんでした: ${reason}`, file);
  }
  const document = parseYaml(text, file);
  return validateDocument(document, onWarning);
}

/**
 * 生のルール定義を検証し、索引付きの `ResolvedRuleSet` へ変換する。
 *
 * 検証内容:
 * - `id` の必須・一意性（重複は後勝ち。位置は最初の宣言を保つ）
 * - `member` / `identifier` / `call` のいずれか 1 つ以上の指定
 * - `sinks[].severity` が `error | warning | note`
 * - `sinks[].kinds` が空でない
 * - `taintedArgs` が 0 以上の整数
 *
 * `kinds: []` のサニタイザは「すべてのタグ」を意味するため、解決時に
 * ソース／シンクが生成するタグ集合（無ければタグ語彙）へ展開する。
 */
export function resolveRuleSet(raw: Partial<ResolvedRuleSet>, onWarning?: WarningSink): ResolvedRuleSet {
  const options: NormalizeOptions = onWarning === undefined ? {} : { onWarning };
  const warn = (message: string, path: string): void => onWarning?.(message, path);

  const sources = dedupeById(
    normalizeRuleList<SourceSpec>(raw.sources, 'rules.sources', normalizeSourceSpec, options),
    'rules.sources',
    warn,
  );
  const sinks = dedupeById(
    normalizeRuleList<SinkSpec>(raw.sinks, 'rules.sinks', normalizeSinkSpec, options),
    'rules.sinks',
    warn,
  );
  const vocabulary = collectVocabulary(sources, sinks);
  const sanitizers = dedupeById(
    normalizeRuleList<SanitizerSpec>(raw.sanitizers, 'rules.sanitizers', normalizeSanitizerSpec, options),
    'rules.sanitizers',
    warn,
  ).map((spec) => (spec.kinds.length > 0 ? spec : { ...spec, kinds: vocabulary }));
  const propagators = dedupePatterns(normalizeRuleList<PatternSpec>(raw.propagators, 'rules.propagators', normalizePropagator, options));
  const ignorePaths = raw.ignorePaths === undefined ? [] : [...raw.ignorePaths];

  const sinkById = new Map<string, SinkSpec>();
  for (const spec of sinks) sinkById.set(spec.id, spec);
  const sourceById = new Map<string, SourceSpec>();
  for (const spec of sources) sourceById.set(spec.id, spec);
  const sanitizerById = new Map<string, SanitizerSpec>();
  for (const spec of sanitizers) sanitizerById.set(spec.id, spec);

  return {
    sources: [...sources],
    sanitizers: [...sanitizers],
    sinks: [...sinks],
    propagators: [...propagators],
    ignorePaths,
    sinkById,
    sourceById,
    sanitizerById,
  };
}

/** `id` 重複を後勝ちで解決する（最初の宣言位置を保つ）。 */
function dedupeById<T extends { readonly id: string }>(items: readonly T[], path: string, warn: WarningSink): T[] {
  const result: T[] = [];
  const indexById = new Map<string, number>();
  let position = -1;
  for (const item of items) {
    position += 1;
    const index = indexById.get(item.id);
    if (index === undefined) {
      indexById.set(item.id, result.length);
      result.push(item);
      continue;
    }
    warn(`id "${item.id}" が重複しています。後から定義された内容で上書きします`, `${path}[${position}]`);
    result[index] = item;
  }
  return result;
}

/** 伝播規則の重複を取り除く（同じ条件の規則は 1 つに畳む）。 */
function dedupePatterns(items: readonly PatternSpec[]): PatternSpec[] {
  const result: PatternSpec[] = [];
  const seen = new Set<string>();
  for (const item of items) {
    const key = `${item.member ?? ''}|${item.identifier ?? ''}|${item.call ?? ''}|${item.allowDynamic === true ? '1' : '0'}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(item);
  }
  return result;
}

/** ソース／シンクが生成するタグ語彙（無ければドキュメント上の語彙）。 */
function collectVocabulary(sources: readonly SourceSpec[], sinks: readonly SinkSpec[]): string[] {
  const kinds = new Set<string>();
  for (const source of sources) for (const kind of source.kinds) kinds.add(kind);
  for (const sink of sinks) for (const kind of sink.kinds) kinds.add(kind);
  if (kinds.size === 0) for (const kind of TAG_VOCABULARY) kinds.add(kind);
  return [...kinds].sort();
}

/**
 * 設定を解決して `TaintConfig` を返す。
 *
 * `origin` には実際に使った設定ファイルの絶対パス、組み込み既定のみなら `'builtin'` が入る。
 * 例外は投げずに `onWarning` へ流す問題（未知キーなど）以外は、すべて `ConfigError` として報告する。
 */
export async function resolveConfig(options: ResolveConfigOptions): Promise<TaintConfig> {
  const onWarning = options.onWarning;
  const file = await findConfigFile(options);
  const document = file === undefined ? undefined : await readConfigDocument(file, onWarning);

  // --- ルール: 組み込みへ追記（同一 id は後勝ち） ---
  const rules = ruleSetFromDocument(document ?? EMPTY_DOCUMENT, onWarning);

  // --- 解析: 既定 → ファイル → CLI 上書き（浅いマージ） ---
  const fromFile = document?.analysis;
  const overrides = options.overrides;
  const maxCallDepth = overrides?.maxCallDepth ?? fromFile?.maxCallDepth ?? DEFAULT_ANALYSIS.maxCallDepth;
  const maxIterations = fromFile?.maxIterations ?? DEFAULT_ANALYSIS.maxIterations;
  const kinds = overrides?.kinds ?? fromFile?.kinds;
  const dedupe = fromFile?.dedupe ?? DEFAULT_ANALYSIS.dedupe;
  const analysis = {
    maxCallDepth,
    maxIterations,
    ...(kinds !== undefined ? { kinds: [...kinds] } : {}),
    ...(dedupe !== undefined ? { dedupe } : {}),
  };

  // --- 出力: 既定 → ファイル → CLI 上書き ---
  const fileOutput = document?.output;
  const format: OutputConfig['format'] = overrides?.format ?? fileOutput?.format ?? DEFAULT_OUTPUT.format;
  const outputPath = overrides?.output ?? fileOutput?.output;
  const failOn: OutputConfig['failOn'] = overrides?.failOn ?? fileOutput?.failOn ?? DEFAULT_OUTPUT.failOn;
  const output: OutputConfig = {
    format,
    ...(outputPath !== undefined ? { output: outputPath } : {}),
    ...(failOn !== undefined ? { failOn } : {}),
  };

  return {
    schemaVersion: 1,
    rules,
    analysis,
    output,
    origin: file ?? 'builtin',
  };
}

/** 検証済みドキュメントからルールセットを組み立てる（`resolveConfig` の内部処理を単体で使う場合）。 */
export function ruleSetFromDocument(document: ValidatedDocument, onWarning?: WarningSink): ResolvedRuleSet {
  const sources = [...BUILTIN_SOURCES, ...document.rules.sources];
  const sanitizers = [...BUILTIN_SANITIZERS, ...document.rules.sanitizers];
  const sinks = [...BUILTIN_SINKS, ...document.rules.sinks];
  const propagators = [...BUILTIN_PROPAGATORS, ...document.rules.propagators];
  const ignorePaths = document.rules.ignorePaths !== undefined ? [...document.rules.ignorePaths] : [...DEFAULT_IGNORE_PATHS];
  return resolveRuleSet({ sources, sanitizers, sinks, propagators, ignorePaths }, onWarning);
}
