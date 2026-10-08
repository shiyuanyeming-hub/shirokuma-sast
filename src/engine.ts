/**
 * スキャンのオーケストレーション。
 *
 * パイプライン: 探索 → 解析（IR 構築） → ルール適用 → データフロー解析 → レポート
 *
 * 各段は独立にテストできるよう分離してある。このファイルは
 * 「順番に呼び、結果を 1 つにまとめる」ことだけを担当する。
 */
import path from 'node:path';
import { solveGraph } from './analysis/solver.js';
import { resolveConfig } from './config/loader.js';
import { discoverFiles } from './discovery.js';
import { buildIR } from './ir/builder.js';
import { annotate } from './rules/annotate.js';
import type { ResolvedRuleSet } from './types.js';
import { meetsSeverity, toPosixPath } from './util/impl.js';
import type {
  AnalysisHints,
  AnalysisResult,
  AnalysisStats,
  Diagnostic,
  Finding,
  ScanOptions,
  Severity,
  TaintConfig,
  ToolInfo,
} from './types.js';

/** エンジンとレポート形式のバージョン。出力の互換性判定に使う。 */
export const ENGINE_VERSION = '0.1.0';
export const TOOL_NAME = 'shirokuma-sast';
export const TOOL_VERSION = '0.1.0';

/** 解析エンジンが必要とする追加入力。 */
export interface RunOptions extends ScanOptions {
  /** IR 構築が返した補助情報。省略時は空として扱う。 */
  readonly hints?: AnalysisHints;
  /** 統計の上書き（テストで固定したい場合）。 */
  readonly statsOverride?: Partial<AnalysisStats>;
}

const EMPTY_HINTS: AnalysisHints = { callbackLinks: new Map(), unresolvedCallees: [] };

/**
 * レポートの相対パスを計算する基準ディレクトリ。
 *
 * 単一ファイルを対象にした場合、そのファイル自身を基準にすると
 * 相対パスが空文字になり、レポートの位置情報が壊れる。
 * そのためファイル指定時は親ディレクトリを基準にする。
 */
export function scanRootOf(target: string): string {
  return path.resolve(target);
}

/** 対象が 1 ファイルなら、相対パスの基準はその親ディレクトリにする。 */
function projectRootFor(target: string, files: readonly string[]): string {
  const resolved = path.resolve(target);
  if (files.length === 1 && path.resolve(files[0] ?? resolved) === resolved) {
    return path.dirname(resolved);
  }
  return resolved;
}

/** 解析対象を探索し、設定を解決する（解析はまだ行わない）。 */
export async function prepare(options: ScanOptions): Promise<{
  files: readonly string[];
  config: TaintConfig;
  diagnostics: readonly Diagnostic[];
}> {
  const root = scanRootOf(options.root);
  const config = options.config ?? (await resolveConfig({ root }));

  options.onProgress?.({ phase: 'discover', current: 0, total: 0 });
  const discovered = await discoverFiles({
    root,
    ...(options.include === undefined ? {} : { include: options.include }),
    exclude: [...config.rules.ignorePaths, ...(options.exclude ?? [])],
  });

  // 設定の `ignorePaths` は探索側でも効かせる（二重の防御）。
  return { files: discovered.files, config, diagnostics: discovered.diagnostics };
}

/** 1 回のスキャンを実行して結果を返す。 */
export async function scan(options: RunOptions): Promise<AnalysisResult> {
  const started = Date.now();
  const { files, config, diagnostics: discoveryDiagnostics } = await prepare(options);
  const rules = config.rules;
  // 相対パスの基準。単一ファイル指定でも壊れないよう projectRootFor で決める。
  const root = projectRootFor(options.root, files);

  options.onProgress?.({ phase: 'ir', current: 0, total: files.length });
  const irResult = await buildIR({
    files,
    root,
    ...(options.onProgress === undefined ? {} : { onProgress: options.onProgress }),
  });

  options.onProgress?.({ phase: 'rules', current: 0, total: irResult.graph.functions.length });
  const annotated = annotate(irResult.graph, rules);

  options.onProgress?.({ phase: 'solve', current: 0, total: 1 });
  const analysis = solveGraph(
    {
      graph: irResult.graph,
      sources: annotated.sources,
      sanitizers: annotated.sanitizers,
      sinks: annotated.sinks,
    },
    rules,
    {
      hints: options.hints ?? irResult.hints,
      maxIterationsPerFunction: config.analysis.maxIterations,
      dedupe: config.analysis.dedupe ?? true,
    },
  );

  const findings = filterKinds(analysis.findings, config.analysis.kinds);
  const diagnostics: Diagnostic[] = [...discoveryDiagnostics, ...irResult.diagnostics, ...analysis.diagnostics];

  options.onProgress?.({ phase: 'report', current: 1, total: 1 });

  const stats: AnalysisStats = {
    filesScanned: irResult.files.length,
    functionsAnalysed: irResult.graph.functions.filter((fn) => fn.analysable && fn.isModuleScope !== true).length,
    flowNodes: irResult.graph.nodes.length,
    flowEdges: irResult.graph.edges.length,
    iterations: analysis.stats.iterations,
    truncated: analysis.stats.truncated,
    elapsedMs: Date.now() - started,
    ...(options.statsOverride ?? {}),
  };

  const tool: ToolInfo = {
    name: TOOL_NAME,
    version: TOOL_VERSION,
    engineVersion: ENGINE_VERSION,
    configOrigin: config.origin,
  };

  return {
    schemaVersion: 1,
    tool,
    files: irResult.files.map((file) => ({
      ...file,
      relativePath: toPosixPath(file.relativePath),
    })),
    findings,
    stats,
    diagnostics,
  };
}

/** 設定で指定されたタグだけを残す。 */
function filterKinds(findings: readonly Finding[], kinds: readonly string[] | undefined): readonly Finding[] {
  if (kinds === undefined || kinds.length === 0) {
    return findings;
  }
  const allowed = new Set(kinds);
  return findings.filter((finding) => finding.kinds.some((kind) => allowed.has(kind)));
}

/** CI ゲートの判定。`failOn` 以上に重大な検出が 1 件でもあれば true。 */
export function shouldFail(result: AnalysisResult, threshold: Severity | 'none'): boolean {
  if (threshold === 'none') {
    return false;
  }
  return result.findings.some((finding) => meetsSeverity(finding.severity, threshold));
}

/** 重要度ごとの件数。レポートのサマリに使う。 */
export function countBySeverity(findings: readonly Finding[]): Readonly<Record<Severity, number>> {
  const counts: Record<Severity, number> = { error: 0, warning: 0, note: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

/** 解析結果を 1 行の要約にする（CLI と CI ログ用）。 */
export function summarize(result: AnalysisResult): string {
  const counts = countBySeverity(result.findings);
  return [
    `検出 ${result.findings.length} 件`,
    `(error ${counts.error} / warning ${counts.warning} / note ${counts.note})`,
    `| ファイル ${result.stats.filesScanned}`,
    `| 関数 ${result.stats.functionsAnalysed}`,
    `| ノード ${result.stats.flowNodes}`,
    `| 辺 ${result.stats.flowEdges}`,
    `| 反復 ${result.stats.iterations}`,
    `| ${result.stats.elapsedMs ?? 0}ms`,
  ].join(' ');
}

export { EMPTY_HINTS };
export type { ResolvedRuleSet };
