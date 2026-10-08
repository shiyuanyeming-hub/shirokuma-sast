/**
 * 解析エンジンのテスト用フィクスチャ。
 *
 * IR 構築（`src/ir/builder.ts`）は別担当が並行して実装しているため、
 * 解析エンジンのテストは IR に依存させない。ここで `IRGraph` と
 * `AnnotatedGraph` をリテラルに組み立て、解析の意味論だけを固定する。
 */

import type { AnnotatedGraph } from '../../src/rules/annotate-contract.js';
import type {
  AnalysisHints,
  CallSite,
  FlowEdge,
  FlowKind,
  FlowNode,
  FunctionIR,
  IRGraph,
  ParamIR,
  PatternSpec,
  Range,
  ResolvedRuleSet,
  SanitizerOccurrence,
  SanitizerSpec,
  Severity,
  SinkOccurrence,
  SinkSpec,
  SourceOccurrence,
  SourceSpec,
} from '../../src/types.js';

/** 1 点だけの範囲を作る（テストでは開始位置だけを問題にすることが多い）。 */
export function at(line: number, column = 1): Range {
  return { start: { line, column }, end: { line, column } };
}

/** 開始・終了を明示した範囲を作る。 */
export function span(
  startLine: number,
  startColumn: number,
  endLine: number,
  endColumn: number,
): Range {
  return { start: { line: startLine, column: startColumn }, end: { line: endLine, column: endColumn } };
}

/** 仮引数を作る。 */
export function makeParam(
  name: string,
  index: number,
  extra: { readonly optional?: boolean; readonly rest?: boolean; readonly destructured?: readonly string[] } = {},
): ParamIR {
  return {
    name,
    index,
    optional: extra.optional ?? false,
    rest: extra.rest ?? false,
    ...(extra.destructured !== undefined ? { destructured: extra.destructured } : {}),
  };
}

/** 関数 IR を作る（既定は解析対象・引数なし・呼び出し先なし）。 */
export function makeFunction(input: {
  readonly id: string;
  readonly file: string;
  readonly range?: Range;
  readonly name?: string;
  readonly className?: string;
  readonly params?: readonly ParamIR[];
  readonly callees?: readonly string[];
  readonly analysable?: boolean;
  readonly bodyRange?: Range;
  readonly isModuleScope?: boolean;
}): FunctionIR {
  const name = input.name ?? input.id.split('::')[1] ?? input.id;
  return {
    id: input.id,
    name,
    ...(input.className !== undefined ? { className: input.className } : {}),
    file: input.file,
    range: input.range ?? at(1),
    params: input.params ?? [],
    bodyRange: input.bodyRange ?? at(1),
    callees: input.callees ?? [],
    analysable: input.analysable ?? true,
    ...(input.isModuleScope !== undefined ? { isModuleScope: input.isModuleScope } : {}),
  };
}

/** DFG ノードを作る。 */
export function makeNode(input: {
  readonly id: string;
  readonly kind: FlowKind;
  readonly functionId: string;
  readonly range?: Range;
  readonly label?: string;
  readonly resolvedCallees?: readonly string[];
  readonly text?: string;
}): FlowNode {
  return {
    id: input.id,
    kind: input.kind,
    functionId: input.functionId,
    range: input.range ?? at(1),
    label: input.label ?? input.id,
    ...(input.resolvedCallees !== undefined ? { resolvedCallees: input.resolvedCallees } : {}),
    ...(input.text !== undefined ? { text: input.text } : {}),
  };
}

/** DFG 辺を作る。 */
export function makeEdge(
  from: string,
  to: string,
  kind: FlowEdge['kind'] = 'assign',
  argIndex?: number,
): FlowEdge {
  return { from, to, kind, ...(argIndex !== undefined ? { argIndex } : {}) };
}

/** 呼び出しサイトを作る。 */
export function makeCallSite(
  nodeId: string,
  callerId: string,
  calleeIds: readonly string[],
  text = '',
  range: Range = at(1),
): CallSite {
  return { nodeId, callerId, calleeIds, text, range };
}

/** ソース出現を作る。 */
export function makeSource(input: {
  readonly nodeId: string;
  readonly sourceId: string;
  readonly kinds: readonly string[];
  readonly functionId: string;
  readonly range?: Range;
  readonly label?: string;
}): SourceOccurrence {
  return {
    nodeId: input.nodeId,
    sourceId: input.sourceId,
    kinds: input.kinds,
    functionId: input.functionId,
    range: input.range ?? at(1),
    label: input.label ?? input.nodeId,
  };
}

/** サニタイザ出現を作る（既定は `valid: true`）。 */
export function makeSanitizer(input: {
  readonly nodeId: string;
  readonly sanitizerId: string;
  readonly kinds?: readonly string[];
  readonly valid?: boolean;
  readonly invalidReason?: string;
  readonly functionId: string;
  readonly range?: Range;
}): SanitizerOccurrence {
  return {
    nodeId: input.nodeId,
    sanitizerId: input.sanitizerId,
    kinds: input.kinds ?? [],
    valid: input.valid ?? true,
    ...(input.invalidReason !== undefined ? { invalidReason: input.invalidReason } : {}),
    functionId: input.functionId,
    range: input.range ?? at(1),
  };
}

/** シンク出現を作る（`taintedArgs` の既定は空 = すべての引数）。 */
export function makeSink(input: {
  readonly nodeId: string;
  readonly sinkId: string;
  readonly functionId: string;
  readonly range?: Range;
  readonly kinds?: readonly string[];
  readonly severity?: Severity;
  readonly message?: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly label?: string;
  readonly taintedArgs?: readonly number[];
}): SinkOccurrence {
  return {
    nodeId: input.nodeId,
    sinkId: input.sinkId,
    kinds: input.kinds ?? ['sql'],
    severity: input.severity ?? 'error',
    message: input.message ?? `${input.sinkId} に汚染が到達しました`,
    ...(input.advice !== undefined ? { advice: input.advice } : {}),
    ...(input.cwe !== undefined ? { cwe: input.cwe } : {}),
    functionId: input.functionId,
    range: input.range ?? at(1),
    label: input.label ?? input.nodeId,
    taintedArgs: input.taintedArgs ?? [],
  };
}

/** ソース定義を作る。 */
export function makeSourceSpec(
  id: string,
  kinds: readonly string[],
  extra: { readonly description?: string } = {},
): SourceSpec {
  return { id, kinds, ...(extra.description !== undefined ? { description: extra.description } : {}) };
}

/** サニタイザ定義を作る。 */
export function makeSanitizerSpec(id: string, kinds: readonly string[]): SanitizerSpec {
  return { id, kinds };
}

/** シンク定義を作る。 */
export function makeSinkSpec(
  id: string,
  kinds: readonly string[],
  extra: { readonly severity?: Severity; readonly message?: string; readonly taintedArgs?: readonly number[] } = {},
): SinkSpec {
  return {
    id,
    kinds,
    severity: extra.severity ?? 'error',
    message: extra.message ?? `${id} の検出`,
    ...(extra.taintedArgs !== undefined ? { taintedArgs: extra.taintedArgs } : {}),
  };
}

/** ルールセットのフィクスチャ入力。 */
export interface RuleFixtureInput {
  readonly sources?: readonly SourceSpec[];
  readonly sanitizers?: readonly SanitizerSpec[];
  readonly sinks?: readonly SinkSpec[];
  readonly propagators?: readonly PatternSpec[];
  readonly ignorePaths?: readonly string[];
}

/** 解決済みルールセットを組み立てる（索引 `Map` も一緒に作る）。 */
export function makeRules(input: RuleFixtureInput = {}): ResolvedRuleSet {
  const sources = input.sources ?? [];
  const sanitizers = input.sanitizers ?? [];
  const sinks = input.sinks ?? [];
  return {
    sources,
    sanitizers,
    sinks,
    propagators: input.propagators ?? [],
    ignorePaths: input.ignorePaths ?? [],
    sinkById: new Map(sinks.map((sink) => [sink.id, sink])),
    sourceById: new Map(sources.map((source) => [source.id, source])),
    sanitizerById: new Map(sanitizers.map((sanitizer) => [sanitizer.id, sanitizer])),
  };
}

/** 解析フィクスチャの入力。 */
export interface AnalysisFixtureInput {
  readonly functions: readonly FunctionIR[];
  readonly nodes: readonly FlowNode[];
  readonly edges: readonly FlowEdge[];
  readonly callSites?: readonly CallSite[];
  readonly sources?: readonly SourceOccurrence[];
  readonly sanitizers?: readonly SanitizerOccurrence[];
  readonly sinks?: readonly SinkOccurrence[];
  /** 明示的なルールセット（省略時は出現から自動生成する）。 */
  readonly rules?: RuleFixtureInput;
  /** コールバック配線（`AnalysisHints`）。 */
  readonly hints?: AnalysisHints;
}

/** 解析フィクスチャ（入力グラフとルールセットの組）。 */
export interface AnalysisFixture {
  readonly graph: AnnotatedGraph;
  readonly rules: ResolvedRuleSet;
  /** コールバック配線（未指定なら空の配線）。 */
  readonly hints: AnalysisHints;
}

/** 配線が無いときの既定値。 */
export const EMPTY_HINTS: AnalysisHints = { callbackLinks: new Map(), unresolvedCallees: [] };

/** 出現情報からルールセットを自動生成する（テストの記述量を減らすため）。 */
function deriveRules(
  sources: readonly SourceOccurrence[],
  sanitizers: readonly SanitizerOccurrence[],
  sinks: readonly SinkOccurrence[],
): ResolvedRuleSet {
  const sourceSpecs = new Map<string, SourceSpec>();
  for (const source of sources) {
    if (!sourceSpecs.has(source.sourceId)) {
      sourceSpecs.set(source.sourceId, { id: source.sourceId, kinds: source.kinds });
    }
  }
  const sanitizerSpecs = new Map<string, SanitizerSpec>();
  for (const sanitizer of sanitizers) {
    if (!sanitizerSpecs.has(sanitizer.sanitizerId)) {
      sanitizerSpecs.set(sanitizer.sanitizerId, { id: sanitizer.sanitizerId, kinds: sanitizer.kinds });
    }
  }
  const sinkSpecs = new Map<string, SinkSpec>();
  for (const sink of sinks) {
    if (sinkSpecs.has(sink.sinkId)) continue;
    sinkSpecs.set(sink.sinkId, {
      id: sink.sinkId,
      kinds: sink.kinds,
      severity: sink.severity,
      message: sink.message,
      ...(sink.cwe !== undefined ? { cwe: sink.cwe } : {}),
    });
  }
  return makeRules({
    sources: [...sourceSpecs.values()],
    sanitizers: [...sanitizerSpecs.values()],
    sinks: [...sinkSpecs.values()],
  });
}

/**
 * グラフ・出現・ルールをまとめて組み立てる。
 * `graph.functionsByFile` / `nodeById` / `functionById` の索引もここで張る。
 */
export function makeAnalysis(input: AnalysisFixtureInput): AnalysisFixture {
  const functions = input.functions;
  const nodes = input.nodes;
  const edges = input.edges;
  const callSites = input.callSites ?? [];
  const sources = input.sources ?? [];
  const sanitizers = input.sanitizers ?? [];
  const sinks = input.sinks ?? [];

  const functionsByFile = new Map<string, string[]>();
  for (const fn of functions) {
    const bucket = functionsByFile.get(fn.file);
    if (bucket === undefined) functionsByFile.set(fn.file, [fn.id]);
    else bucket.push(fn.id);
  }
  for (const bucket of functionsByFile.values()) bucket.sort();

  const ir: IRGraph = {
    functions,
    nodes,
    edges,
    callSites,
    functionsByFile,
    nodeById: new Map(nodes.map((node) => [node.id, node])),
    functionById: new Map(functions.map((fn) => [fn.id, fn])),
  };

  return {
    graph: { graph: ir, sources, sanitizers, sinks },
    rules: input.rules !== undefined ? makeRules(input.rules) : deriveRules(sources, sanitizers, sinks),
    hints: input.hints ?? EMPTY_HINTS,
  };
}
