/**
 * ルール適用（アノテーション）— モジュールコントラクト
 *
 * 実装担当はこのファイルのシグネチャを変更しないこと。
 *
 * 責務: `IRGraph` と `ResolvedRuleSet` を突き合わせ、
 * 「どのノードがソース／サニタイザ／シンクか」を確定させる。
 *
 * 照合規則（すべて実装し、テストで固定すること）:
 * - `member`: `child_process.exec` のようなドット区切り。AST のプロパティアクセス連鎖を
 *   そのまま比較する。`require('child_process').exec` のような分割 require も解決する。
 * - `identifier`: 単純識別子。引数名・変数名に一致。
 * - `call`: 呼び出し式の名前。`member` を伴わない裸の関数呼び出し。
 * - `withinFunctions`: ソースが現れてよい関数名の許可リスト。
 * - プロパティアクセス（`req.query.id` など）は **接頭辞一致で最も長いもの** を採用する。
 *   例: `req.query` がソースなら `req.query.id` もソース。
 * - サニタイザの `validation`:
 *   - `static-sql`: 第 1 引数がテンプレートリテラル（補間なし）または文字列リテラルの
 *     ときだけ有効。`db.query(sql)` で `sql` が変数なら **無効**（＝汚染は残る）。
 *   - `constant-argument`: 指定引数がリテラルであること。
 *   - `none`: 常に有効。
 * - 無効なサニタイザは `valid: false` とし、`invalidReason` に日本語の理由を入れる。
 */
import type { IRGraph, ResolvedRuleSet, SanitizerOccurrence, SinkOccurrence, SourceOccurrence } from '../types.js';

// ---------------------------------------------------------------------------
// パターン照合器
// ---------------------------------------------------------------------------

/** パターン照合器に渡す、解決済みのメンバ式・識別子・呼び出し名。 */
export interface ResolvedExpression {
  /** 正規化したメンバ式（例: `child_process.exec`）。裸の識別子なら undefined。 */
  readonly member?: string;
  /** メンバ式の末尾セグメント（例: `exec`）。 */
  readonly last?: string;
  /** 単純識別子または宣言名（例: `req`）。 */
  readonly identifier?: string;
  /** 呼び出し式か。 */
  readonly isCall: boolean;
  /** 呼び出しの引数テキスト（`isCall` のとき）。 */
  readonly argTexts: readonly string[];
  /** 第 1 引数がリテラル（文字列 or 補間なしテンプレート）か。 */
  readonly firstArgIsLiteral: boolean;
}

/** パターン定義が、この式に一致するか。 */
export declare function matchesPattern(
  pattern: { readonly member?: string; readonly identifier?: string; readonly call?: string; readonly allowDynamic?: boolean },
  expr: ResolvedExpression,
): boolean;

/** 複数のパターンのうち、最も長く一致したものを返す（もっとも具体的な規則を優先）。 */
export declare function matchMostSpecific<T extends { readonly member?: string; readonly identifier?: string; readonly call?: string }>(
  patterns: readonly T[],
  expr: ResolvedExpression,
): T | undefined;

/**
 * プロパティアクセス連鎖を `a.b.c` 形式へ正規化する。
 * 解決できない場合は undefined。`require('m')` は `m` として解決する。
 */
export declare function resolveMemberChain(expression: unknown): string | undefined;

// ---------------------------------------------------------------------------
// アノテーション本体
// ---------------------------------------------------------------------------

export interface AnnotateResult {
  readonly sources: readonly SourceOccurrence[];
  readonly sanitizers: readonly SanitizerOccurrence[];
  readonly sinks: readonly SinkOccurrence[];
}

/**
 * グラフ全体へルールを適用する。
 * 戻り値の配列順は決定的（ノード ID → ルール ID の順）でなければならない。
 */
export declare function annotate(graph: IRGraph, rules: ResolvedRuleSet): AnnotateResult;

/** `annotate` の結果をグラフへ結びつけた、解析エンジンの入力。 */
export interface AnnotatedGraph {
  readonly graph: IRGraph;
  readonly sources: readonly SourceOccurrence[];
  readonly sanitizers: readonly SanitizerOccurrence[];
  readonly sinks: readonly SinkOccurrence[];
}
