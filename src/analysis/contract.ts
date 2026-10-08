/**
 * 解析エンジン（ワークリスト法）— モジュールコントラクト
 *
 * 実装担当はこのファイルのシグネチャを変更しないこと。
 */

import type { AnnotatedGraph } from '../rules/annotate-contract.js';
import type { AnalysisStats, Finding, ResolvedRuleSet } from '../types.js';

/** `analyze` の結果。`stats` はグラフ規模も含め完全な形で返すこと。 */
export interface AnalyzeResult {
  readonly findings: readonly Finding[];
  readonly stats: AnalysisStats;
}

/**
 * アノテーション済みグラフ上でワークリスト法による汚染伝播を実行し、検出を返す。
 *
 * アルゴリズム要件:
 * 1. 各ソース出現ノードに初期汚染トークンを投入する。
 * 2. ワークリストが空になるまで、辺に沿ってトークンを伝播する。
 *    - `assign` / `property`: そのまま伝播
 *    - `argument`: 引数位置を記録して伝播
 *    - `summary`: 関数サマリ経由（引数 → 戻り値）で伝播
 * 3. サニタイザ出現ノードを通過する際、`valid: true` なら該当タグを落とす。
 *    タグがすべて落ちたトークンは伝播を停止する。
 * 4. シンク出現ノードに汚染トークンが到達したら検出を作る。
 *    - `taintedArgs` が指定されていれば、その引数位置経由の到達のみ報告する。
 *    - `kinds` の交差が空なら報告しない。
 * 5. 再帰・相互再帰は不動点まで反復する。`maxIterations` を超えたら
 *    `stats.truncated` に関数 ID を積み、診断として残す（無限ループ禁止）。
 *
 * 出力要件:
 * - `findings` は決定的な順序（ファイル → 行 → 列 → ruleId）。
 * - 各 `Finding.proof` は `source` → `propagate`* → `sink` の順で、
 *   実際に辿ったノード列を反映する。経路上にサニタイザがあれば `sanitize` を含める。
 * - 同一 (ruleId, file, range) の重複は既定で抑制する（`dedupe`）。
 */
export declare function analyze(graph: AnnotatedGraph, rules: ResolvedRuleSet): AnalyzeResult;

/** 1 関数分のサマリを計算する（呼び出し元解析で再利用する内部 API）。 */
export declare function summarizeFunction(
  graph: AnnotatedGraph,
  functionId: string,
  rules: ResolvedRuleSet,
): import('../types.js').FunctionSummary;
