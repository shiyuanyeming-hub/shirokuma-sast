/**
 * 関数サマリ — 引数 → 戻り値 / 引数 → シンク の要約を不動点計算から抽出する。
 *
 * 汚染解析の不動点（`solver.ts` のワークリスト）は、すべての関数を同時に解く
 * 1 本の計算として実行される。再帰・相互再帰はその中で自然に収束する。
 * 本モジュールはその観測結果から「この関数はどの引数の汚染を戻り値へ通すか」
 * 「どの引数の汚染がどのシンクへ届くか」を読み取り、呼び出し元の解析や
 * レポートで再利用できる形にする。
 *
 * サマリの求め方:
 * - 各仮引数ノードへ記号トークン（`WILDCARD_KIND` = 未知のタグ）を投入する。
 *   未知タグは「任意のタグが来る可能性がある」ことを表す。
 * - 記号トークンがその関数の `return` ノード（または関数外へ出る `return` 辺の直前）へ
 *   到達すれば `taintedReturnFromParams` に、シンクへ到達すれば `paramToSink` に入る。
 * - サニタイザでタグが落ちれば、その経路はサマリに含まれない。
 */

import type { AnnotatedGraph } from '../rules/annotate-contract.js';
import type { FunctionSummary, ParamSinkFlow, ResolvedRuleSet } from '../types.js';
import { UNKNOWN_ARG_INDEX, solveGraph, type ParamFlowObservation, type SolveOutcome } from './solver.js';

/** `summarizeFunction` / `buildSummaryTable` の調整パラメータ。 */
export interface SummaryOptions {
  /** 1 関数あたりの反復上限（打ち切り検出のため）。 */
  readonly maxIterations?: number;
}

/** ロケール非依存の文字列比較（決定的な整列のため）。 */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/**
 * 1 関数分のサマリを計算する（呼び出し元解析で再利用する内部 API）。
 *
 * 対象関数にスコープを絞って解析するため、返る `findings` は
 * 「その関数内のシンクで確定した検出」だけになる。
 * 反復上限に達して打ち切られた場合は `converged: false` を返す。
 */
export function summarizeFunction(
  graph: AnnotatedGraph,
  functionId: string,
  rules: ResolvedRuleSet,
): FunctionSummary {
  const outcome = solveGraph(graph, rules, { scopeFunctionId: functionId, seedParamTokens: true });
  return buildSummary(functionId, outcome);
}

/**
 * すべての関数のサマリを 1 回の不動点計算からまとめて作る。
 *
 * 関数ごとに `summarizeFunction` を呼ぶより状態空間を共有できるため、
 * プロジェクト全体のサマリ表が必要な場合はこちらを使う。
 */
export function buildSummaryTable(
  graph: AnnotatedGraph,
  rules: ResolvedRuleSet,
  options: SummaryOptions = {},
): ReadonlyMap<string, FunctionSummary> {
  const outcome = solveGraph(graph, rules, { seedParamTokens: true, ...options });
  const table = new Map<string, FunctionSummary>();
  const functionIds = [...graph.graph.functions.map((fn) => fn.id)].sort(compareStrings);
  for (const functionId of functionIds) table.set(functionId, buildSummary(functionId, outcome));
  return table;
}

/** 1 回の解析結果から、指定関数のサマリを読み取る。 */
function buildSummary(functionId: string, outcome: SolveOutcome): FunctionSummary {
  const taintedParams = new Set<number>();
  const flows: ParamSinkFlow[] = [];
  const seen = new Set<string>();

  for (const observation of outcome.paramFlows) {
    if (observation.functionId !== functionId) continue;
    if (observation.kind === 'return') {
      taintedParams.add(observation.paramIndex);
      continue;
    }
    const key = [
      observation.paramIndex,
      observation.sinkId,
      observation.sinkArgIndex,
      observation.range.start.line,
      observation.range.start.column,
    ].join('\u0000');
    if (seen.has(key)) continue;
    seen.add(key);
    flows.push({
      paramIndex: observation.paramIndex,
      sinkId: observation.sinkId,
      sinkArgIndex: observation.sinkArgIndex,
      range: observation.range,
    });
  }

  flows.sort(
    (a, b) =>
      a.paramIndex - b.paramIndex ||
      compareStrings(a.sinkId, b.sinkId) ||
      a.sinkArgIndex - b.sinkArgIndex ||
      a.range.start.line - b.range.start.line ||
      a.range.start.column - b.range.start.column,
  );

  return {
    functionId,
    taintedReturnFromParams: [...taintedParams].sort((a, b) => a - b),
    paramToSink: flows,
    findings: outcome.findings.filter((finding) => finding.functionId === functionId),
    converged: !outcome.stats.truncated.includes(functionId),
  };
}

/**
 * サマリ観測の補助: 引数位置を特定できなかった `paramToSink` は
 * `sinkArgIndex === UNKNOWN_ARG_INDEX`（-1）になる。
 * `taintedArgs` 未指定のシンクでは引数位置を問わないため、この値は異常ではない。
 */
export const UNRESOLVED_SINK_ARG_INDEX = UNKNOWN_ARG_INDEX;

/** サマリ観測の生データ（診断・テスト用）。 */
export type { ParamFlowObservation };
