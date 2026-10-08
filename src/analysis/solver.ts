/**
 * 汚染伝播ソルバ — ワークリスト法によるデータフロー解析の中核。
 *
 * アルゴリズム:
 * 1. `AnnotatedGraph.sources` の各出現ノードへ初期トークン（ソース ID + タグ集合）を投入する。
 * 2. ワークリストから状態 `(ノード, ソース, タグ集合, 直前の引数位置)` を取り出し、
 *    出辺に沿って後続状態を生成する。`assign` / `property` / `return` / `summary` は
 *    タグをそのまま運び、`argument` は引数位置を更新して運ぶ。
 * 3. 到達したノードにサニタイザ出現があれば、`valid: true` のものだけが
 *    対応するタグを落とす。タグが尽きたトークンはそこで伝播を停止する
 *    （`valid: false` のサニタイザは何も落とさない = 汚染は残る）。
 * 4. シンク出現ノードへ到達したら `taintedArgs`（引数位置）とタグの交差を検査し、
 *    条件を満たすときだけ検出を作る。
 * 5. 関数境界は 2 種類の補助辺で越える:
 *    「呼び出しノード → 呼び出し先の仮引数ノード（引数位置 i）」
 *    「呼び出し先の return ノード → 呼び出し元の呼び出しノード」。
 *    IR が既に同じ役割の関数横断辺を持っている場合は二重配線を避けるため合成しない
 *    （IR 構築側の実装差異を吸収する）。
 *
 * 終了保証:
 * - 状態は `(ノード, ソース, タグ集合, 引数位置)` で重複排除されるため状態空間は有限で、
 *   再帰・相互再帰は不動点で自然に停止する。
 * - さらに 1 関数あたりの反復上限を設け、超過した関数 ID を `stats.truncated` と
 *   診断に記録する（無限ループ禁止）。
 *
 * 決定性:
 * - 初期トークンはソース出現の位置順、出辺は `(to, kind, argIndex)` 順に処理する。
 * - 検出は `(ファイル, 行, 列, ruleId)` の全順序で整列する。
 */

import type { AnnotatedGraph } from '../rules/annotate-contract.js';
import type {
  AnalysisHints,
  AnalysisStats,
  Diagnostic,
  Finding,
  FlowEdge,
  FlowKind,
  FlowNode,
  FunctionIR,
  Position,
  ProofStep,
  Range,
  ResolvedRuleSet,
  SanitizerOccurrence,
  SanitizerUse,
  SinkOccurrence,
  SourceOccurrence,
  TaintToken,
} from '../types.js';
import type { AnalyzeResult } from './contract.js';
import { DEFAULT_MAX_ITERATIONS_PER_BUCKET, runWorklist } from './worklist.js';

/** 契約（`analysis/contract.ts`）で定義された解析結果型の再輸出。 */
export type { AnalyzeResult };

/** 既定の 1 関数あたり反復上限（ワークリストのバケット上限と同義）。 */
export const DEFAULT_MAX_ITERATIONS_PER_FUNCTION = DEFAULT_MAX_ITERATIONS_PER_BUCKET;

/**
 * 既定の再帰展開上限（`maxCallDepth` 未指定時）。
 * 同じ関数へ再入する回数の上限であり、非再帰の呼び出し連鎖は制限しない。
 */
export const DEFAULT_MAX_CALL_DEPTH = 5;

/** 記号的な引数ソース（サマリ計算専用）の ID 接頭辞。 */
export const PARAM_SOURCE_PREFIX = 'param:';

/** 未知のタグを表すワイルドカード。引数サマリの計算でのみ使う。 */
export const WILDCARD_KIND = '*';

/** 引数位置を特定できなかったことを表す番兵値（サマリ用）。 */
export const UNKNOWN_ARG_INDEX = -1;

/** 解析の調整パラメータ。`analyze` は既定値で動く。 */
export interface SolveOptions {
  /** 1 関数あたりの反復上限（`AnalysisConfig.maxIterations`）。 */
  readonly maxIterationsPerFunction?: number;
  /** `maxIterationsPerFunction` の別名（設定ファイルの項目名に合わせた形）。 */
  readonly maxIterations?: number;
  /**
   * 再帰的な呼び出し文脈を何段まで区別するか（`AnalysisConfig.maxCallDepth`）。
   * 経路上で既に訪れた関数へ再入する回数の上限として使う。
   * 非再帰の呼び出し連鎖は制限しないため、通常のコードで検出を落とさない。
   * `0` 以下は「文脈を区別しない（無制限）」を意味する。
   */
  readonly maxCallDepth?: number;
  /** 報告するタグの許可リスト（`AnalysisConfig.kinds`）。 */
  readonly kinds?: readonly string[];
  /** 同一 (ruleId, ファイル, 範囲) の重複検出を抑制するか（既定 `true`）。 */
  readonly dedupe?: boolean;
  /** 引数サマリ用の記号トークンを投入するか（既定 `false`）。 */
  readonly seedParamTokens?: boolean;
  /** 指定した場合、検出とサマリ観測をその関数だけに限定する。 */
  readonly scopeFunctionId?: string;
  /**
   * IR 構築が渡す補助情報。`callbackLinks` により、高階関数
   * （`arr.map(x => ...)` や `app.get('/x', (req, res) => ...)`）の
   * 呼び出しノードからコールバックの仮引数ノードへ汚染を流す。
   */
  readonly hints?: AnalysisHints;
}

/** 記号的トークンが観測した「引数 → 戻り値」「引数 → シンク」の関係。 */
export type ParamFlowObservation =
  | {
      readonly kind: 'return';
      readonly functionId: string;
      readonly paramIndex: number;
      readonly range: Range;
    }
  | {
      readonly kind: 'sink';
      readonly functionId: string;
      readonly paramIndex: number;
      readonly sinkId: string;
      readonly sinkArgIndex: number;
      readonly range: Range;
    };

/** ソルバの完全な出力（`analyze` はこの部分集合を返す）。 */
export interface SolveOutcome {
  readonly findings: readonly Finding[];
  readonly stats: AnalysisStats;
  /** 記号トークンが観測した引数フロー（サマリ計算用）。 */
  readonly paramFlows: readonly ParamFlowObservation[];
  readonly diagnostics: readonly Diagnostic[];
}

// ---------------------------------------------------------------------------
// 公開 API
// ---------------------------------------------------------------------------

/**
 * アノテーション済みグラフ上でワークリスト法による汚染伝播を実行し、検出を返す。
 *
 * 契約上 `AnalysisConfig` は受け取らないため、重複排除は常に有効
 * （`AnalysisConfig.dedupe !== false` の既定挙動）で動作する。
 */
export function analyze(graph: AnnotatedGraph, rules: ResolvedRuleSet): AnalyzeResult {
  const outcome = solveGraph(graph, rules);
  return { findings: outcome.findings, stats: outcome.stats };
}

/**
 * 調整パラメータ付きの解析。`analyze` と同じ計算を、打ち切り上限や
 * 重複排除の切り替え、スコープ限定つきで実行する。
 */
export function solveGraph(
  graph: AnnotatedGraph,
  rules: ResolvedRuleSet,
  options: SolveOptions = {},
): SolveOutcome {
  return new Solver(graph, rules, resolveOptions(options)).run();
}

// ---------------------------------------------------------------------------
// タグ集合の操作
// ---------------------------------------------------------------------------

/** ロケール非依存の文字列比較（決定的な整列のため）。 */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/** タグ集合を重複除去して昇順に整列する。 */
export function normalizeKinds(kinds: readonly string[]): readonly string[] {
  return [...new Set(kinds)].sort(compareStrings);
}

/**
 * タグ集合の交差。
 * - `targets` が空なら「すべてのタグ」とみなし、元のタグを返す。
 * - `WILDCARD_KIND` は未知のタグを表し、相手側の具体的なタグをそのまま採用する。
 */
export function intersectKinds(kinds: readonly string[], targets: readonly string[]): readonly string[] {
  if (targets.length === 0) return normalizeKinds(kinds);
  const concrete = kinds.filter((kind) => kind !== WILDCARD_KIND);
  const hits = concrete.filter((kind) => targets.includes(kind));
  if (hits.length > 0) return normalizeKinds(hits);
  if (kinds.includes(WILDCARD_KIND)) return normalizeKinds(targets);
  return [];
}

/**
 * サニタイザによるタグ除去。
 * - `sanitizedKinds` が空なら「すべてのタグ」を落とす（`SanitizerSpec.kinds` の契約）。
 * - `WILDCARD_KIND`（未知のタグ）は具体的なタグ指定では落とさない。
 *   未知のタグが別種であり得るため、保守的に残す。
 */
export function removeKinds(
  kinds: readonly string[],
  sanitizedKinds: readonly string[],
): { readonly kept: readonly string[]; readonly dropped: readonly string[] } {
  if (sanitizedKinds.length === 0) return { kept: [], dropped: normalizeKinds(kinds) };
  const dropped = kinds.filter((kind) => kind !== WILDCARD_KIND && sanitizedKinds.includes(kind));
  if (dropped.length === 0) return { kept: kinds, dropped: [] };
  const kept = kinds.filter((kind) => !dropped.includes(kind));
  return { kept, dropped: normalizeKinds(dropped) };
}

// ---------------------------------------------------------------------------
// グラフ索引
// ---------------------------------------------------------------------------

/** 仮引数ノードと `ParamIR.index` の対応。 */
interface ParamNodeBinding {
  readonly index: number;
  readonly nodeId: string;
  readonly name: string;
}

/** 解析ホットパスで参照する索引一式。 */
interface GraphIndex {
  readonly annotated: AnnotatedGraph;
  readonly functions: ReadonlyMap<string, FunctionIR>;
  readonly nodes: ReadonlyMap<string, FlowNode>;
  readonly outgoing: ReadonlyMap<string, readonly FlowEdge[]>;
  readonly incoming: ReadonlyMap<string, readonly FlowEdge[]>;
  readonly sourcesAtNode: ReadonlyMap<string, readonly SourceOccurrence[]>;
  readonly sanitizersAtNode: ReadonlyMap<string, readonly SanitizerOccurrence[]>;
  readonly sinksAtNode: ReadonlyMap<string, readonly SinkOccurrence[]>;
  /** 呼び出しノード ID → 解決済み呼び出し先の関数 ID。 */
  readonly calleesByCallNode: ReadonlyMap<string, readonly string[]>;
  /** 関数 ID → その関数を呼んでいる呼び出しノード ID。 */
  readonly callNodesByFunction: ReadonlyMap<string, readonly string[]>;
  /** 関数 ID → その関数の return ノード ID。 */
  readonly returnNodesByFunction: ReadonlyMap<string, readonly string[]>;
  /** 関数 ID → 仮引数ノードの対応（index 昇順）。 */
  readonly paramsByFunction: ReadonlyMap<string, readonly ParamNodeBinding[]>;
  readonly fileByFunction: ReadonlyMap<string, string>;
}

function appendTo<K, V>(map: Map<K, V[]>, key: K, value: V): void {
  const list = map.get(key);
  if (list === undefined) map.set(key, [value]);
  else list.push(value);
}

function dedupeSorted(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort(compareStrings);
}

/** `file.ts::Class.method` 形式の関数 ID から相対パス部分を取り出す。 */
function relativePathOfId(functionId: string): string {
  const separator = functionId.indexOf('::');
  return separator > 0 ? functionId.slice(0, separator) : functionId;
}

/** 記号的引数ソース ID を組み立てる。 */
export function symbolicSourceId(functionId: string, paramIndex: number): string {
  return `${PARAM_SOURCE_PREFIX}${functionId}#${paramIndex}`;
}

function compareEdges(a: FlowEdge, b: FlowEdge): number {
  return (
    compareStrings(a.to, b.to) ||
    compareStrings(a.kind, b.kind) ||
    (a.argIndex ?? UNKNOWN_ARG_INDEX) - (b.argIndex ?? UNKNOWN_ARG_INDEX)
  );
}

/** 位置の昇順比較（行 → 列）。 */
function comparePositions(a: Position, b: Position): number {
  return a.line - b.line || a.column - b.column;
}

/** 範囲の開始位置による昇順比較。 */
function compareRanges(a: Range, b: Range): number {
  return comparePositions(a.start, b.start);
}

/** `outer` が `inner` を完全に含むか（同一範囲も含むとみなす）。 */
function rangeContains(outer: Range, inner: Range): boolean {
  return comparePositions(outer.start, inner.start) <= 0 && comparePositions(outer.end, inner.end) >= 0;
}

/**
 * 仮引数ノードと `ParamIR` を対応づける。
 * ラベル一致（分割代入はプロパティ名でも可）を優先し、対応が取れない分は
 * 出現位置順で埋める。
 */
function bindParamNodes(fn: FunctionIR, nodes: readonly FlowNode[]): readonly ParamNodeBinding[] {
  const candidates = [...nodes].sort((a, b) => compareStrings(a.id, b.id));
  const used = new Set<string>();
  const bindings: ParamNodeBinding[] = [];

  for (const param of fn.params) {
    const match = candidates.find(
      (node) =>
        !used.has(node.id) &&
        (node.label === param.name || (param.destructured?.includes(node.label) ?? false)),
    );
    if (match === undefined) continue;
    used.add(match.id);
    bindings.push({ index: param.index, nodeId: match.id, name: param.name });
  }

  const remaining = candidates.filter((node) => !used.has(node.id));
  for (const param of fn.params) {
    if (bindings.some((binding) => binding.index === param.index)) continue;
    const next = remaining.shift();
    if (next === undefined) break;
    bindings.push({ index: param.index, nodeId: next.id, name: param.name });
  }

  return bindings.sort((a, b) => a.index - b.index);
}

function buildIndex(annotated: AnnotatedGraph): GraphIndex {
  const graph = annotated.graph;

  const functions = new Map<string, FunctionIR>();
  for (const fn of graph.functions) functions.set(fn.id, fn);

  const nodes = new Map<string, FlowNode>();
  for (const node of graph.nodes) nodes.set(node.id, node);

  const outgoing = new Map<string, FlowEdge[]>();
  const incoming = new Map<string, FlowEdge[]>();
  for (const edge of graph.edges) {
    appendTo(outgoing, edge.from, edge);
    appendTo(incoming, edge.to, edge);
  }
  for (const list of outgoing.values()) list.sort(compareEdges);
  for (const list of incoming.values()) list.sort(compareEdges);

  const sourcesAtNode = new Map<string, SourceOccurrence[]>();
  for (const occurrence of annotated.sources) {
    appendTo(sourcesAtNode, occurrence.nodeId, occurrence);
  }
  const sanitizersAtNode = new Map<string, SanitizerOccurrence[]>();
  for (const occurrence of annotated.sanitizers) {
    appendTo(sanitizersAtNode, occurrence.nodeId, occurrence);
  }
  const sinksAtNode = new Map<string, SinkOccurrence[]>();
  for (const occurrence of annotated.sinks) {
    appendTo(sinksAtNode, occurrence.nodeId, occurrence);
  }
  for (const list of sinksAtNode.values()) list.sort((a, b) => compareStrings(a.sinkId, b.sinkId));

  const calleesByCallNode = new Map<string, string[]>();
  for (const node of graph.nodes) {
    for (const calleeId of node.resolvedCallees ?? []) appendTo(calleesByCallNode, node.id, calleeId);
  }
  for (const site of graph.callSites) {
    for (const calleeId of site.calleeIds) appendTo(calleesByCallNode, site.nodeId, calleeId);
  }
  const calleeIndex = new Map<string, readonly string[]>();
  for (const [key, list] of calleesByCallNode) calleeIndex.set(key, dedupeSorted(list));

  const callerAccumulator = new Map<string, string[]>();
  for (const [callNodeId, calleeIds] of calleeIndex) {
    for (const calleeId of calleeIds) appendTo(callerAccumulator, calleeId, callNodeId);
  }
  const callNodesByFunction = new Map<string, readonly string[]>();
  for (const [key, list] of callerAccumulator) callNodesByFunction.set(key, dedupeSorted(list));

  const returnAccumulator = new Map<string, string[]>();
  for (const node of graph.nodes) {
    if (node.kind === 'return') appendTo(returnAccumulator, node.functionId, node.id);
  }
  const returnNodesByFunction = new Map<string, readonly string[]>();
  for (const [key, list] of returnAccumulator) returnNodesByFunction.set(key, dedupeSorted(list));

  const paramsByFunction = new Map<string, readonly ParamNodeBinding[]>();
  const functionIds = [...functions.keys()].sort(compareStrings);
  const nodesByFunction = new Map<string, FlowNode[]>();
  for (const node of graph.nodes) appendTo(nodesByFunction, node.functionId, node);
  for (const functionId of functionIds) {
    const fn = functions.get(functionId);
    if (fn === undefined || fn.params.length === 0) continue;
    const own = (nodesByFunction.get(functionId) ?? []).filter((node) => node.kind === 'param');
    if (own.length === 0) continue;
    paramsByFunction.set(functionId, bindParamNodes(fn, own));
  }

  const fileByFunction = new Map<string, string>();
  for (const fn of graph.functions) fileByFunction.set(fn.id, fn.file);

  return {
    annotated,
    functions,
    nodes,
    outgoing,
    incoming,
    sourcesAtNode,
    sanitizersAtNode,
    sinksAtNode,
    calleesByCallNode: calleeIndex,
    callNodesByFunction,
    returnNodesByFunction,
    paramsByFunction,
    fileByFunction,
  };
}

// ---------------------------------------------------------------------------
// 状態
// ---------------------------------------------------------------------------

/** 経路上で適用されたサニタイザの記録（`path` のインデックス付き）。 */
interface SanitizeMark {
  readonly pathIndex: number;
  readonly uses: readonly SanitizerUse[];
}

/** ワークリスト上の 1 状態。契約の `TaintToken` を核に補助情報を添える。 */
interface SolveState {
  readonly token: TaintToken;
  readonly functionId: string;
  /** 直前の辺が `argument` のときだけ設定される引数位置。 */
  readonly argIndex: number | undefined;
  /** 経路上のサニタイズ適用位置（証明の組み立てに使う）。 */
  readonly sanitizeMarks: readonly SanitizeMark[];
  /** 経路上で越えた関数境界（再帰検出と `maxCallDepth` の判定に使う）。 */
  readonly enteredFunctions: readonly string[];
  /** 引数サマリ用の記号トークンか。 */
  readonly symbolic: boolean;
}

function stateKey(state: SolveState): string {
  return [
    state.token.nodeId,
    state.token.sourceId,
    state.token.kinds.join(','),
    state.argIndex === undefined ? '-' : String(state.argIndex),
  ].join('\u0000');
}

/** 記号トークンの持ち主（どの関数の何番目の引数か）。 */
interface ParamOwner {
  readonly functionId: string;
  readonly paramIndex: number;
}

interface ResolvedSolveOptions {
  readonly maxIterations: number;
  readonly maxCallDepth: number;
  readonly kinds: readonly string[] | undefined;
  readonly dedupe: boolean;
  readonly seedParamTokens: boolean;
  readonly scopeFunctionId: string | undefined;
  readonly hints: AnalysisHints | undefined;
}

function resolveOptions(options: SolveOptions): ResolvedSolveOptions {
  return {
    maxIterations:
      options.maxIterationsPerFunction ?? options.maxIterations ?? DEFAULT_MAX_ITERATIONS_PER_FUNCTION,
    maxCallDepth: options.maxCallDepth ?? DEFAULT_MAX_CALL_DEPTH,
    kinds: options.kinds,
    dedupe: options.dedupe ?? true,
    seedParamTokens: options.seedParamTokens ?? false,
    scopeFunctionId: options.scopeFunctionId,
    hints: options.hints,
  };
}

/**
 * シンクの `taintedArgs` による引数位置の絞り込み。
 *
 * `taintedArgs` は **呼び出し式の引数位置** を指す。プロパティ代入
 * （`node.innerHTML = '<h1>' + nickname + '</h1>'`）のように呼び出しではない
 * ノードでは、汚染された値そのものがシンクへ流れ込んでいるため、
 * 引数位置の指定は適用しない（`xss-inner-html` などの検出が落ちる原因になる）。
 *
 * 呼び出しノードでは:
 * - `taintedArgs` が空配列 = すべての引数（`SinkSpec.taintedArgs` 省略時）。
 * - 直前の辺が `argument` でない到達は引数位置を特定できないため、
 *   指定があるときに限り報告しない（誤検出を避ける保守側の判断）。
 */
function argumentAllowed(
  sink: SinkOccurrence,
  argIndex: number | undefined,
  nodeKind: FlowKind,
): boolean {
  if (nodeKind !== 'call') return true;
  if (sink.taintedArgs.length === 0) return true;
  return argIndex !== undefined && sink.taintedArgs.includes(argIndex);
}

/** 1 回の解析（グラフ全体または 1 関数スコープ）を実行する本体。 */
class Solver {
  private readonly index: GraphIndex;
  private readonly rules: ResolvedRuleSet;
  private readonly options: ResolvedSolveOptions;
  private readonly findings: Finding[] = [];
  private readonly paramFlows: ParamFlowObservation[] = [];
  private readonly paramFlowKeys = new Set<string>();
  private readonly diagnostics: Diagnostic[] = [];
  private readonly symbolicOwners = new Map<string, ParamOwner>();
  /** 呼び出しノード ID → コールバックの仮引数ノード ID（`hints.callbackLinks` の索引）。 */
  private readonly callbackParams: ReadonlyMap<string, readonly string[]>;
  /** 再帰展開の上限に達した関数（診断を 1 度だけ積むため）。 */
  private readonly depthCapped = new Set<string>();

  constructor(annotated: AnnotatedGraph, rules: ResolvedRuleSet, options: ResolvedSolveOptions) {
    this.index = buildIndex(annotated);
    this.rules = rules;
    this.options = options;
    this.callbackParams = this.buildCallbackIndex();
  }

  /** 不動点まで反復し、検出と統計を返す。 */
  run(): SolveOutcome {
    const result = runWorklist<SolveState>({
      initial: this.buildSeeds(),
      keyOf: stateKey,
      budgetOf: (state) => state.functionId,
      expand: (state) => this.expand(state),
      onState: (state) => this.observe(state),
      maxIterationsPerBucket: this.options.maxIterations,
      onBucketTruncated: (bucket) => this.recordTruncation(bucket),
    });

    const graph = this.index.annotated.graph;
    const stats: AnalysisStats = {
      filesScanned: graph.functionsByFile.size,
      functionsAnalysed: graph.functions.filter((fn) => fn.analysable).length,
      flowNodes: graph.nodes.length,
      flowEdges: graph.edges.length,
      iterations: result.iterations,
      truncated: result.truncatedBuckets,
    };

    return {
      findings: this.finalizeFindings(),
      stats,
      paramFlows: this.finalizeParamFlows(),
      diagnostics: this.diagnostics,
    };
  }

  // -------------------------------------------------------------------------
  // 初期状態
  // -------------------------------------------------------------------------

  private buildSeeds(): readonly SolveState[] {
    const seeds: SolveState[] = [];

    const sources = [...this.index.annotated.sources].sort(
      (a, b) => compareRanges(a.range, b.range) || compareStrings(a.nodeId, b.nodeId),
    );
    for (const occurrence of sources) {
      if (occurrence.kinds.length === 0) continue;
      const seed = this.createSeed(occurrence.nodeId, occurrence.sourceId, occurrence.kinds, false);
      if (seed !== undefined) seeds.push(seed);
    }

    if (this.options.seedParamTokens) seeds.push(...this.paramSeeds());
    return seeds;
  }

  private paramSeeds(): readonly SolveState[] {
    const seeds: SolveState[] = [];
    const functionIds = [...this.index.paramsByFunction.keys()].sort(compareStrings);
    for (const functionId of functionIds) {
      const bindings = this.index.paramsByFunction.get(functionId) ?? [];
      for (const binding of bindings) {
        const sourceId = symbolicSourceId(functionId, binding.index);
        this.symbolicOwners.set(sourceId, { functionId, paramIndex: binding.index });
        const seed = this.createSeed(binding.nodeId, sourceId, [WILDCARD_KIND], true);
        if (seed !== undefined) seeds.push(seed);
      }
    }
    return seeds;
  }

  private createSeed(
    nodeId: string,
    sourceId: string,
    kinds: readonly string[],
    symbolic: boolean,
  ): SolveState | undefined {
    const node = this.index.nodes.get(nodeId);
    if (node === undefined) return undefined;
    const initialKinds = normalizeKinds(kinds);
    if (initialKinds.length === 0) return undefined;
    const sanitized = this.sanitizeAt(node, initialKinds);
    if (sanitized.kinds.length === 0) return undefined;
    return {
      token: {
        sourceId,
        kinds: sanitized.kinds,
        nodeId,
        path: [nodeId],
        sanitized: sanitized.uses,
      },
      functionId: node.functionId,
      argIndex: undefined,
      sanitizeMarks: sanitized.uses.length > 0 ? [{ pathIndex: 0, uses: sanitized.uses }] : [],
      enteredFunctions: [],
      symbolic,
    };
  }

  /**
   * コールバック配線（`hints.callbackLinks`）を索引化する。
   *
   * `callbackLinks` は「呼び出しノード → コールバックの仮引数ノード」の対応を持ち、
   * 高階関数（`arr.map(x => ...)` / `app.get('/x', (req, res) => ...)`）で
   * 呼び出し側の汚染をコールバック本体へ流すために使う。
   * グラフに存在しないノードを指す配線は診断として残す（黙って落とさない）。
   */
  private buildCallbackIndex(): ReadonlyMap<string, readonly string[]> {
    const index = new Map<string, readonly string[]>();
    const links = this.options.hints?.callbackLinks;
    if (links === undefined) return index;

    const callNodeIds = [...links.keys()].sort(compareStrings);
    for (const callNodeId of callNodeIds) {
      const entries = links.get(callNodeId) ?? [];
      const params: string[] = [];
      for (const entry of entries) {
        for (const pair of entry.pairs) {
          if (!this.index.nodes.has(pair.paramNodeId)) {
            this.diagnostics.push({
              level: 'warning',
              message: `コールバック配線が参照する仮引数ノード ${pair.paramNodeId} がグラフに存在しません（呼び出し ${callNodeId}）`,
            });
            continue;
          }
          params.push(pair.paramNodeId);
        }
      }
      const unique = dedupeSorted(params);
      if (unique.length > 0) index.set(callNodeId, unique);
    }
    return index;
  }

  // -------------------------------------------------------------------------
  // 伝播
  // -------------------------------------------------------------------------

  /**
   * ノード上のサニタイザを適用する。
   * `valid: false` のものは何も落とさない（汚染は残る）。
   * 実際にタグを落としたサニタイザだけを `uses` に記録する。
   */
  private sanitizeAt(
    node: FlowNode,
    kinds: readonly string[],
  ): { readonly kinds: readonly string[]; readonly uses: readonly SanitizerUse[] } {
    const occurrences = this.index.sanitizersAtNode.get(node.id);
    if (occurrences === undefined || occurrences.length === 0) return { kinds, uses: [] };

    let current = kinds;
    const uses: SanitizerUse[] = [];
    for (const occurrence of occurrences) {
      if (!occurrence.valid) continue;
      const result = removeKinds(current, occurrence.kinds);
      if (result.dropped.length > 0) {
        uses.push({ sanitizerId: occurrence.sanitizerId, kinds: result.dropped, nodeId: node.id });
      }
      current = result.kept;
    }
    return { kinds: current, uses };
  }

  /** 辺を 1 本たどって後続状態を作る。タグが尽きた場合は `undefined`。 */
  private advance(
    state: SolveState,
    target: FlowNode,
    argIndex: number | undefined,
    enteredFunction?: string,
  ): SolveState | undefined {
    const sanitized = this.sanitizeAt(target, state.token.kinds);
    if (sanitized.kinds.length === 0) return undefined;
    const pathIndex = state.token.path.length;
    const token: TaintToken = {
      sourceId: state.token.sourceId,
      kinds: sanitized.kinds,
      nodeId: target.id,
      path: [...state.token.path, target.id],
      sanitized:
        sanitized.uses.length > 0 ? [...state.token.sanitized, ...sanitized.uses] : state.token.sanitized,
    };
    return {
      token,
      functionId: target.functionId,
      argIndex,
      sanitizeMarks:
        sanitized.uses.length > 0
          ? [...state.sanitizeMarks, { pathIndex, uses: sanitized.uses }]
          : state.sanitizeMarks,
      enteredFunctions:
        enteredFunction === undefined
          ? state.enteredFunctions
          : [...state.enteredFunctions, enteredFunction],
      symbolic: state.symbolic,
    };
  }

  private expand(state: SolveState): readonly SolveState[] {
    const node = this.index.nodes.get(state.token.nodeId);
    if (node === undefined) return [];

    const successors: SolveState[] = [];
    for (const edge of this.index.outgoing.get(node.id) ?? []) {
      const target = this.index.nodes.get(edge.to);
      if (target === undefined) continue;
      if (edge.kind === 'return') this.observeReturnExit(state, node, target);
      if (this.leavesScope(edge, target)) continue;
      // 引数位置は「直前に通過した argument 辺」だけを根拠にする（推測しない）。
      const nextArgIndex = edge.kind === 'argument' ? edge.argIndex : undefined;
      const next = this.advance(state, target, nextArgIndex);
      if (next !== undefined) successors.push(next);
    }

    for (const next of this.crossFunctionSuccessors(state, node)) successors.push(next);
    for (const next of this.callbackSuccessors(state, node)) successors.push(next);
    return successors;
  }

  /**
   * コールバック配線に沿って、呼び出しノードの汚染をコールバックの仮引数へ流す。
   *
   * 呼び出しノード → 仮引数ノード → （本体） → コールバックの return ノード →
   * 呼び出しノード、という循環が生じ得るが、状態の重複排除によって有限回で収束する
   * （IR 構築側は `returnNodeId -> callNodeId` の `return` 辺を既に張っているため、
   * ここで戻り値の辺を追加しない）。
   */
  private callbackSuccessors(state: SolveState, node: FlowNode): readonly SolveState[] {
    const paramNodeIds = this.callbackParams.get(node.id);
    if (paramNodeIds === undefined) return [];

    const successors: SolveState[] = [];
    for (const paramNodeId of paramNodeIds) {
      const paramNode = this.index.nodes.get(paramNodeId);
      if (paramNode === undefined) continue;
      if (this.exceedsCallDepth(state, paramNode.functionId)) continue;
      // コールバック本体へ入る時点で引数位置はリセットする。
      const next = this.advance(state, paramNode, undefined, paramNode.functionId);
      if (next !== undefined) successors.push(next);
    }
    return successors;
  }

  /** スコープ限定時、呼び出し元へ戻る `return` 辺は要約に不要なので打ち切る。 */
  private leavesScope(edge: FlowEdge, target: FlowNode): boolean {
    const scope = this.options.scopeFunctionId;
    if (scope === undefined) return false;
    return edge.kind === 'return' && target.functionId !== scope;
  }

  /**
   * 関数境界を越える補助辺を合成する。
   * IR が同じ役割の関数横断辺を既に持っている場合は二重配線を避けるため合成しない。
   */
  private crossFunctionSuccessors(state: SolveState, node: FlowNode): readonly SolveState[] {
    const successors: SolveState[] = [];
    const argIndex = state.argIndex;

    if (argIndex !== undefined && argIndex !== UNKNOWN_ARG_INDEX) {
      const callees = this.index.calleesByCallNode.get(node.id) ?? [];
      for (const calleeId of callees) {
        const binding = (this.index.paramsByFunction.get(calleeId) ?? []).find(
          (entry) => entry.index === argIndex,
        );
        if (binding === undefined) continue;
        if (this.hasExternalArgumentEdge(calleeId, binding.nodeId)) continue;
        if (this.exceedsCallDepth(state, calleeId)) continue;
        const paramNode = this.index.nodes.get(binding.nodeId);
        if (paramNode === undefined) continue;
        // 呼び出し先へ入る時点で引数位置は一度リセットする（呼び出し先の
        // シンク位置は呼び出し先自身の `argument` 辺だけが根拠になる）。
        const next = this.advance(state, paramNode, undefined, calleeId);
        if (next !== undefined) successors.push(next);
      }
    }

    if (node.kind === 'return' && !this.hasExternalReturnEdge(node)) {
      const callNodes = this.index.callNodesByFunction.get(node.functionId) ?? [];
      for (const callNodeId of callNodes) {
        const callNode = this.index.nodes.get(callNodeId);
        if (callNode === undefined) continue;
        const next = this.advance(state, callNode, undefined);
        if (next !== undefined) successors.push(next);
      }
    }

    return successors;
  }

  /**
   * 再帰展開の上限（`maxCallDepth`）を超えるか。
   *
   * 経路上で既に訪れた関数へ再入する回数だけを数える。非再帰の呼び出し連鎖
   * （`a → b → c`）は制限しないため、通常のコードの検出を落とさない。
   * `maxCallDepth <= 0` は「呼び出し文脈を区別しない（無制限）」を意味する。
   */
  private exceedsCallDepth(state: SolveState, functionId: string): boolean {
    const limit = this.options.maxCallDepth;
    if (limit <= 0) return false;
    let reentries = 0;
    for (const entered of state.enteredFunctions) {
      if (entered === functionId) reentries += 1;
    }
    if (reentries < limit) return false;
    if (!this.depthCapped.has(functionId)) {
      this.depthCapped.add(functionId);
      const fn = this.index.functions.get(functionId);
      this.diagnostics.push({
        level: 'info',
        message: `再帰の展開が上限 ${limit} 段に達したため、関数 ${functionId} への再入を打ち切りました`,
        ...(fn !== undefined ? { file: fn.file, range: fn.range } : {}),
      });
    }
    return true;
  }

  /** 仮引数ノードが既に他関数からの `argument` 辺を受けているか。 */
  private hasExternalArgumentEdge(calleeId: string, paramNodeId: string): boolean {
    for (const edge of this.index.incoming.get(paramNodeId) ?? []) {
      if (edge.kind !== 'argument') continue;
      const from = this.index.nodes.get(edge.from);
      if (from !== undefined && from.functionId !== calleeId) return true;
    }
    return false;
  }

  /** return ノードが既に他関数へ出る辺を持っているか。 */
  private hasExternalReturnEdge(node: FlowNode): boolean {
    for (const edge of this.index.outgoing.get(node.id) ?? []) {
      const to = this.index.nodes.get(edge.to);
      if (to !== undefined && to.functionId !== node.functionId) return true;
    }
    return false;
  }

  // -------------------------------------------------------------------------
  // 観測（シンク判定とサマリ）
  // -------------------------------------------------------------------------

  private observe(state: SolveState): void {
    const node = this.index.nodes.get(state.token.nodeId);
    if (node === undefined) return;

    const sinks = this.index.sinksAtNode.get(node.id);
    if (sinks !== undefined) {
      for (const sink of sinks) this.considerSink(state, node, sink);
    }

    if (state.symbolic) this.observeParamReturn(state, node);
  }

  private considerSink(state: SolveState, node: FlowNode, sink: SinkOccurrence): void {
    const scope = this.options.scopeFunctionId;
    if (scope !== undefined && node.functionId !== scope) return;

    // ルールセットに存在しないシンク出現は、アノテーション結果の不整合として無視する。
    const spec = this.rules.sinkById.get(sink.sinkId);
    if (spec === undefined) return;

    const kinds = intersectKinds(state.token.kinds, sink.kinds);
    if (kinds.length === 0) return;
    if (!argumentAllowed(sink, state.argIndex, node.kind)) return;

    // 記号トークン（引数サマリ用）は検出を作らない。呼び出し元の実ソースから
    // 到達した時点で、そちらのトークンが検出を作る（二重報告の防止）。
    if (state.symbolic) {
      this.recordParamSink(state, node, sink);
      return;
    }

    const functionId = this.index.functions.has(sink.functionId) ? sink.functionId : node.functionId;
    const fn = this.index.functions.get(functionId);
    const relativePath = relativePathOfId(functionId);
    const file = fn !== undefined ? fn.file : relativePath;
    const range = sink.range;

    this.findings.push({
      id: `${sink.sinkId}:${relativePath}:${range.start.line}:${range.start.column}`,
      ruleId: sink.sinkId,
      severity: sink.severity,
      message: sink.message,
      ...(sink.advice !== undefined ? { advice: sink.advice } : {}),
      ...(sink.cwe !== undefined ? { cwe: sink.cwe } : {}),
      kinds,
      sourceId: state.token.sourceId,
      sinkId: sink.sinkId,
      file,
      relativePath,
      range,
      functionId,
      proof: this.buildProof(state, sink),
    });
  }

  private observeParamReturn(state: SolveState, node: FlowNode): void {
    if (node.kind !== 'return') return;
    const owner = this.symbolicOwners.get(state.token.sourceId);
    if (owner === undefined || owner.functionId !== node.functionId) return;
    const key = `return|${owner.functionId}|${owner.paramIndex}|${node.id}`;
    if (this.paramFlowKeys.has(key)) return;
    this.paramFlowKeys.add(key);
    this.paramFlows.push({
      kind: 'return',
      functionId: owner.functionId,
      paramIndex: owner.paramIndex,
      range: node.range,
    });
  }

  /** `return` 辺で関数外へ出る直前の到達も「汚染された戻り値」として記録する。 */
  private observeReturnExit(state: SolveState, from: FlowNode, to: FlowNode): void {
    if (!state.symbolic) return;
    if (to.functionId === from.functionId) return;
    const owner = this.symbolicOwners.get(state.token.sourceId);
    if (owner === undefined || owner.functionId !== from.functionId) return;
    const key = `return-exit|${owner.functionId}|${owner.paramIndex}|${from.id}`;
    if (this.paramFlowKeys.has(key)) return;
    this.paramFlowKeys.add(key);
    this.paramFlows.push({
      kind: 'return',
      functionId: owner.functionId,
      paramIndex: owner.paramIndex,
      range: from.range,
    });
  }

  private recordParamSink(state: SolveState, node: FlowNode, sink: SinkOccurrence): void {
    const owner = this.symbolicOwners.get(state.token.sourceId);
    if (owner === undefined || owner.functionId !== node.functionId) return;
    const sinkArgIndex = state.argIndex ?? UNKNOWN_ARG_INDEX;
    const key = `sink|${owner.functionId}|${owner.paramIndex}|${sink.sinkId}|${sinkArgIndex}|${sink.range.start.line}|${sink.range.start.column}`;
    if (this.paramFlowKeys.has(key)) return;
    this.paramFlowKeys.add(key);
    this.paramFlows.push({
      kind: 'sink',
      functionId: owner.functionId,
      paramIndex: owner.paramIndex,
      sinkId: sink.sinkId,
      sinkArgIndex,
      range: sink.range,
    });
  }

  // -------------------------------------------------------------------------
  // 証明の組み立て
  // -------------------------------------------------------------------------

  private fileOfNode(node: FlowNode): string {
    return this.index.fileByFunction.get(node.functionId) ?? relativePathOfId(node.functionId);
  }

  /** サニタイザの注記（日本語）。 */
  private sanitizerNote(uses: readonly SanitizerUse[]): string {
    const ids = dedupeSorted(uses.map((use) => use.sanitizerId));
    const kinds = normalizeKinds(uses.flatMap((use) => use.kinds));
    return `サニタイザ ${ids.join(', ')} により ${kinds.join(', ')} を無害化`;
  }

  /**
   * 実際に辿ったノード列から証明を組み立てる。
   * `source` → `propagate`/`sanitize`* → `sink` の順で、各ステップに
   * ファイル・範囲・ラベルを付ける（レポートが「なぜ」を説明するための情報）。
   */
  private buildProof(state: SolveState, sink: SinkOccurrence): readonly ProofStep[] {
    const marksByIndex = new Map<number, SanitizerUse[]>();
    for (const mark of state.sanitizeMarks) {
      const existing = marksByIndex.get(mark.pathIndex);
      if (existing === undefined) marksByIndex.set(mark.pathIndex, [...mark.uses]);
      else existing.push(...mark.uses);
    }

    // 自己辺などによる連続重複を畳む（証明は単調な経路として読めるべき）。
    const entries: { readonly nodeId: string; readonly pathIndex: number }[] = [];
    state.token.path.forEach((nodeId, pathIndex) => {
      const previous = entries[entries.length - 1];
      if (previous !== undefined && previous.nodeId === nodeId) return;
      entries.push({ nodeId, pathIndex });
    });

    const steps: ProofStep[] = [];
    const lastIndex = entries.length - 1;
    entries.forEach((entry, position) => {
      const node = this.index.nodes.get(entry.nodeId);
      if (node === undefined) return;
      const uses = marksByIndex.get(entry.pathIndex);
      const sanitizeNote = uses !== undefined && uses.length > 0 ? this.sanitizerNote(uses) : undefined;
      const isSource = position === 0;
      const isSink = position === lastIndex;
      const description = isSource
        ? this.rules.sourceById.get(state.token.sourceId)?.description
        : undefined;
      const base: Pick<ProofStep, 'nodeId' | 'file' | 'range' | 'label'> = {
        nodeId: entry.nodeId,
        file: this.fileOfNode(node),
        range: node.range,
        label: node.label,
      };

      if (isSource) {
        steps.push({
          ...base,
          role: 'source',
          ...(description !== undefined
            ? { note: description }
            : sanitizeNote !== undefined
              ? { note: sanitizeNote }
              : {}),
        });
      }
      if (isSink) {
        steps.push({
          ...base,
          role: 'sink',
          ...(sanitizeNote !== undefined ? { note: sanitizeNote } : {}),
        });
      } else if (!isSource) {
        steps.push({
          ...base,
          role: sanitizeNote !== undefined ? 'sanitize' : 'propagate',
          ...(sanitizeNote !== undefined ? { note: sanitizeNote } : {}),
        });
      }
    });

    if (steps.length === 0) {
      // 経路が空になることは無いが、入力が壊れていても証明は必ず 1 件返す。
      steps.push({
        nodeId: sink.nodeId,
        file: this.index.fileByFunction.get(sink.functionId) ?? relativePathOfId(sink.functionId),
        range: sink.range,
        label: sink.label,
        role: 'sink',
      });
    }
    return steps;
  }

  // -------------------------------------------------------------------------
  // 出力の確定
  // -------------------------------------------------------------------------

  private recordTruncation(functionId: string): void {
    const fn = this.index.functions.get(functionId);
    this.diagnostics.push({
      level: 'warning',
      message: `関数 ${functionId} の解析が反復上限 ${this.options.maxIterations} 回に達したため打ち切りました`,
      ...(fn !== undefined ? { file: fn.file, range: fn.range } : {}),
    });
  }

  /**
   * 検出を決定的な順序へ整列し、タグ許可リストで絞り、既定では重複を畳む。
   *
   * 重複の畳み方は 2 段階:
   * 1. 完全一致キー `(ruleId, ファイル, 範囲)` — 同一シンクへの複数経路を 1 件にする。
   * 2. 包含関係 — 同一 ruleId・同一ファイル・同一開始行で一方が他方を包む場合に
   *    広い方だけを残す（`await axios.get(x)` と `axios.get(x)` の二重報告対策）。
   */
  private finalizeFindings(): readonly Finding[] {
    const allowed = this.options.kinds;
    const sorted = this.findings
      .filter((finding) => allowed === undefined || intersectKinds(finding.kinds, allowed).length > 0)
      .sort(
        (a, b) =>
          compareStrings(a.file, b.file) ||
          compareRanges(a.range, b.range) ||
          compareStrings(a.ruleId, b.ruleId) ||
          compareStrings(a.sourceId, b.sourceId),
      );
    if (!this.options.dedupe) return sorted;

    const seen = new Set<string>();
    const deduped: Finding[] = [];
    for (const finding of sorted) {
      const key = [
        finding.ruleId,
        finding.file,
        finding.range.start.line,
        finding.range.start.column,
        finding.range.end.line,
        finding.range.end.column,
      ].join('\u0000');
      if (seen.has(key)) continue;
      seen.add(key);
      deduped.push(finding);
    }

    // 段階 2: 同一 ruleId・同一ファイル・同一開始行で、範囲が包含関係にある検出を畳む。
    //    `axios.get(endpoint)`（呼び出し式）と `await axios.get(endpoint)`（それを包む式）の
    //    ように、annotate が同じシンク規則を入れ子の式へ二重に出現させると、
    //    1 箇所の脆弱性が 2 件として報告されてしまう。
    //    包含関係があるときは **広い方** を残す（修正すべき式全体を指し、
    //    証明も呼び出し全体を含むため）。`dedupe: false` のときは何も畳まない。
    const kept: Finding[] = [];
    const containersByRuleLine = new Map<string, Range[]>();
    for (const finding of deduped) {
      const key = `${finding.ruleId}\u0000${finding.file}\u0000${finding.range.start.line}`;
      const containers = containersByRuleLine.get(key);
      if (containers !== undefined && containers.some((range) => rangeContains(range, finding.range))) {
        continue;
      }
      kept.push(finding);
      if (containers === undefined) containersByRuleLine.set(key, [finding.range]);
      else containers.push(finding.range);
    }
    return kept;
  }

  private finalizeParamFlows(): readonly ParamFlowObservation[] {
    return [...this.paramFlows].sort(
      (a, b) =>
        compareStrings(a.functionId, b.functionId) ||
        a.paramIndex - b.paramIndex ||
        compareStrings(a.kind, b.kind) ||
        compareRanges(a.range, b.range),
    );
  }
}
