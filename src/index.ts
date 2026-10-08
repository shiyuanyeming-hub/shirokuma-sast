/**
 * shirokuma-sast の公開 API。
 *
 * ライブラリとして使う場合も、CLI として使う場合も、
 * このモジュールが提供する関数だけを知っていればよい。
 *
 * 例:
 * ```ts
 * import { scan, createReporter } from 'shirokuma-sast';
 * const result = await scan({ root: process.cwd() });
 * process.stdout.write(createReporter('sarif').render(result));
 * ```
 */

// スキャンの入口
export { scan, prepare, shouldFail, countBySeverity, summarize, ENGINE_VERSION, TOOL_NAME, TOOL_VERSION } from './engine.js';
export type { RunOptions } from './engine.js';

// 設定
export { ConfigError } from './config/contract.js';
export { resolveConfig, resolveRuleSet, CONFIG_FILE_CANDIDATES } from './config/loader.js';

// 組み込みルール
export {
  BUILTIN_SOURCES,
  BUILTIN_SANITIZERS,
  BUILTIN_SINKS,
  BUILTIN_PROPAGATORS,
  DEFAULT_ANALYSIS,
  DEFAULT_OUTPUT,
  DEFAULT_IGNORE_PATHS,
} from './rules/builtin.js';
export { annotate } from './rules/annotate.js';
export { matchesPattern, matchMostSpecific, resolveMemberChain } from './rules/match.js';
export type { AnnotatedGraph } from './rules/annotate.js';

// IR（中間表現）
export { buildIR, buildIRFromSource, buildFileIR, makeFunctionId, MODULE_SCOPE_ID } from './ir/builder.js';
export type { CallbackLink, SolverHints, BuildIRFullResult } from './ir/builder.js';
export { normalizeLabel, DEFAULT_LABEL_LENGTH } from './ir/label.js';

// 解析エンジン
export { analyze, solveGraph } from './analysis/solver.js';
export type { AnalyzeResult, SolveOptions, SolveOutcome } from './analysis/solver.js';
export { summarizeFunction } from './analysis/summary.js';

// レポータ
export {
  createReporter,
  createPrettyReporter,
  createJsonReporter,
  createSarifReporter,
  createMarkdownReporter,
  validateSarifStructure,
  SARIF_VERSION,
  SARIF_SCHEMA_URI,
} from './reporters/index.js';

// ファイル探索
export { discoverFiles, DEFAULT_EXCLUDE, DEFAULT_EXTENSIONS, isDeclarationFile } from './discovery.js';

// 型
export type {
  AnalysisConfig,
  AnalysisHints,
  AnalysisResult,
  AnalysisStats,
  CallSite,
  Diagnostic,
  Finding,
  FlowEdge,
  FlowKind,
  FlowNode,
  FunctionIR,
  FunctionSummary,
  IRGraph,
  OutputConfig,
  ParamIR,
  PatternSpec,
  Position,
  ProgressEvent,
  ProofStep,
  Range,
  Reporter,
  ResolvedRuleSet,
  RuleSetConfig,
  SanitizerOccurrence,
  SanitizerSpec,
  ScanOptions,
  Severity,
  SinkOccurrence,
  SinkSpec,
  SourceFileInfo,
  SourceOccurrence,
  SourceSpec,
  TaintConfig,
  TaintToken,
  ToolInfo,
} from './types.js';
