/**
 * レポータ — モジュールコントラクト
 *
 * 実装担当はこのファイルのシグネチャを変更しないこと。
 * すべてのレポータは同じ `AnalysisResult` を受け取り、決定的な文字列を返す。
 * 同じ入力に対して 2 回呼んでもバイト単位で同一の出力になること（テストで固定する）。
 */

import type { AnalysisResult, Reporter } from '../types.js';

/** 参考: レポータが受け取る唯一の入力型。 */
export type ReporterInput = AnalysisResult;

/**
 * 人が読む端末出力。
 * - 色は `color` が true のときだけ ANSI エスケープを使う（既定 false）。
 * - 検出ごとに「重要度 / ruleId / 位置 / メッセージ」を出し、続けて汚染経路を
 *   `└─` のツリーで表示する（source → propagate → sink）。
 * - 末尾にサマリ（検出件数・重要度別・ファイル数・所要統計）を出す。
 * - 検出ゼロなら「検出なし」を 1 行で出す。
 */
export declare function createPrettyReporter(options?: { readonly color?: boolean; readonly maxProofSteps?: number }): Reporter;

/** 機械可読 JSON。キー順を固定し、2 スペースインデントで出力する。 */
export declare function createJsonReporter(): Reporter;

/**
 * SARIF 2.1.0。
 * - `runs[0].tool.driver` に `name` / `version` / `informationUri` / `rules` を入れる。
 * - `rules[].id` は `Finding.ruleId`、`helpUri` は CWE へのリンク。
 * - `results[].level` は重要度を SARIF の `error | warning | note` へ写像。
 * - `results[].locations[0].physicalLocation.region` は 1-based の行・列。
 * - `results[].codeFlows[0].threadFlows[0].locations` に汚染経路を入れる
 *   （GitHub Code Scanning が経路を表示できるようにするため）。
 * - `partialFingerprints` に安定 ID を入れる（再実行で同じ指摘として扱われる）。
 */
export declare function createSarifReporter(options?: { readonly informationUri?: string }): Reporter;

/** Markdown。PR コメントや `reports/` への保存に使う。 */
export declare function createMarkdownReporter(options?: { readonly maxFindings?: number }): Reporter;

/** `format` からレポータを引く。未知の形式は例外。 */
export declare function createReporter(
  format: 'pretty' | 'json' | 'sarif' | 'markdown',
  options?: { readonly color?: boolean; readonly informationUri?: string },
): Reporter;

/** SARIF 出力から GitHub Code Scanning が読む最小構造を検証する（テスト補助）。 */
export declare function validateSarifStructure(sarif: string): readonly string[];
