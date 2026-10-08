/**
 * 設定の解決 — モジュールコントラクト
 *
 * 実装担当はこのファイルのシグネチャを変更しないこと。
 * 設定源の優先順位（上が強い）:
 *   1. CLI フラグ相当の `overrides`
 *   2. `--config` で指定されたファイル
 *   3. 探索で見つかった `.shirokuma.yml` / `.shirokuma.yaml`
 *   4. 組み込み既定（`src/rules/builtin.ts`）
 *
 * マージ規則:
 * - `rules.sources` / `sanitizers` / `sinks` / `propagators` は **追記**（id が重複したら後勝ち）。
 * - `ignorePaths` は **置換**（明示指定があれば探索既定を捨てる）。
 * - `analysis` / `output` は浅いマージ。
 *
 * エラー方針:
 * - 構文エラー・型不一致は `ConfigError` を投げ、`path` に `rules.sinks[2].severity`
 *   のような位置を入れる。黙って既定値へ落とさない。
 * - 未知のキーは警告診断として返し、解析は続行する（前方互換）。
 */
import type { OutputConfig, ResolvedRuleSet, TaintConfig } from '../types.js';

/** 設定の読み込み・検証に失敗したことを表す。 */
export class ConfigError extends Error {
  constructor(
    message: string,
    readonly path: string,
    readonly hint?: string,
  ) {
    super(message);
    this.name = 'ConfigError';
  }
}

export interface ResolveConfigOptions {
  /** 解析対象ルート。設定ファイル探索の起点。 */
  readonly root: string;
  /** `--config` で明示指定されたパス。 */
  readonly configPath?: string;
  /** 探索を無効化し、組み込み既定だけを使う。 */
  readonly builtinOnly?: boolean;
  /** CLI フラグ相当の上書き。 */
  readonly overrides?: {
    readonly format?: OutputConfig['format'];
    readonly output?: string;
    readonly failOn?: OutputConfig['failOn'];
    readonly maxCallDepth?: number;
    readonly kinds?: readonly string[];
  };
  /** 読み込み中に得た警告（未知キーなど）を呼び出し側へ渡す。 */
  readonly onWarning?: (message: string, path: string) => void;
}

/**
 * 設定を解決して `TaintConfig` を返す。
 *
 * `origin` には実際に使った設定ファイルの絶対パス、組み込みのみなら `'builtin'` を入れる。
 * `rules` は `resolveRuleSet()` を通した索引付きの形にすること。
 */
export declare function resolveConfig(options: ResolveConfigOptions): Promise<TaintConfig>;

/**
 * 生のルール定義（id 未解決・重複あり）を検証し、索引付きルールセットへ変換する。
 *
 * 検証内容:
 * - `id` の必須・一意性（重複は後勝ち + 警告コールバック）
 * - `member` / `identifier` / `call` のいずれか 1 つ以上の指定
 * - `sinks[].severity` が `error | warning | note` のいずれか
 * - `sinks[].kinds` が空でない
 * - `taintedArgs` が非負整数
 */
export declare function resolveRuleSet(
  raw: Partial<ResolvedRuleSet>,
  onWarning?: (message: string, path: string) => void,
): ResolvedRuleSet;

/** 設定ファイルの探索順（`root` からの相対）。テストで固定するため公開する。 */
export declare const CONFIG_FILE_CANDIDATES: readonly string[];
