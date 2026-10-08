/**
 * JSON レポータ — 機械可読な出力。
 *
 * 設計方針:
 * - キー順を明示的に固定する。`JSON.stringify` はオブジェクトの挿入順を保つため、
 *   入力（`AnalysisResult`）をそのまま渡さず、専用の DTO を組み立ててから直列化する。
 *   これにより同じ値の入力からは常に同じバイト列が得られる。
 * - インデントは 2 スペース、末尾は改行 1 つ。人が `cat` しても差分を見ても扱いやすい。
 * - 省略可能なフィールドは「値があるときだけ」キーを出す。`null` は混ぜない
 *   （`exactOptionalPropertyTypes` と同じ思想で、欠落と空値を区別する）。
 * - 検出の並び順は入力のまま尊重する。正準順序（file → line → column → ruleId）を
 *   決めるのは解析エンジンの責務であり、レポータは並べ替えない。
 */

import type {
  AnalysisResult,
  Diagnostic,
  Finding,
  ProofStep,
  Range,
  Reporter,
  SourceFileInfo,
} from '../types.js';

/** シリアライズ後の位置（1-based）。 */
interface JsonPosition {
  readonly line: number;
  readonly column: number;
}

/** シリアライズ後の範囲。 */
interface JsonRange {
  readonly start: JsonPosition;
  readonly end: JsonPosition;
}

/** シリアライズ後の実行経路 1 ステップ。 */
interface JsonProofStep {
  readonly nodeId: string;
  readonly role: ProofStep['role'];
  readonly file: string;
  readonly range: JsonRange;
  readonly label: string;
  readonly note?: string;
}

/** シリアライズ後の検出。 */
interface JsonFinding {
  readonly id: string;
  readonly ruleId: string;
  readonly severity: Finding['severity'];
  readonly message: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly kinds: readonly string[];
  readonly sourceId: string;
  readonly sinkId: string;
  readonly file: string;
  readonly relativePath: string;
  readonly range: JsonRange;
  readonly functionId: string;
  readonly proof: readonly JsonProofStep[];
}

/** シリアライズ後の診断。 */
interface JsonDiagnostic {
  readonly level: Diagnostic['level'];
  readonly message: string;
  readonly file?: string;
  readonly range?: JsonRange;
}

/** シリアライズ後の解析統計。 */
interface JsonStats {
  readonly filesScanned: number;
  readonly functionsAnalysed: number;
  readonly flowNodes: number;
  readonly flowEdges: number;
  readonly iterations: number;
  readonly truncated: readonly string[];
}

/** シリアライズ後のスキャン対象ファイル。 */
interface JsonFile {
  readonly path: string;
  readonly relativePath: string;
  readonly hash: string;
  readonly lineCount: number;
}

/** 出力ドキュメント全体。キーの並びがそのまま出力順になる。 */
interface JsonDocument {
  readonly schemaVersion: number;
  readonly tool: {
    readonly name: string;
    readonly version: string;
    readonly engineVersion: string;
    readonly configOrigin: string;
  };
  readonly stats: JsonStats;
  readonly findings: readonly JsonFinding[];
  readonly diagnostics: readonly JsonDiagnostic[];
  readonly files: readonly JsonFile[];
}

/** 範囲を DTO へ変換する。位置は 1-based のまま保持する。 */
function toRange(range: Range): JsonRange {
  return {
    start: { line: range.start.line, column: range.start.column },
    end: { line: range.end.line, column: range.end.column },
  };
}

/** 経路ステップを DTO へ変換する。`note` は存在するときだけキーを出す。 */
function toProofStep(step: ProofStep): JsonProofStep {
  return {
    nodeId: step.nodeId,
    role: step.role,
    file: step.file,
    range: toRange(step.range),
    label: step.label,
    ...(step.note === undefined ? {} : { note: step.note }),
  };
}

/** 検出を DTO へ変換する。省略可能なフィールドは値があるときだけキーを出す。 */
function toFinding(finding: Finding): JsonFinding {
  return {
    id: finding.id,
    ruleId: finding.ruleId,
    severity: finding.severity,
    message: finding.message,
    ...(finding.advice === undefined ? {} : { advice: finding.advice }),
    ...(finding.cwe === undefined ? {} : { cwe: [...finding.cwe] }),
    kinds: [...finding.kinds],
    sourceId: finding.sourceId,
    sinkId: finding.sinkId,
    file: finding.file,
    relativePath: finding.relativePath,
    range: toRange(finding.range),
    functionId: finding.functionId,
    proof: finding.proof.map(toProofStep),
  };
}

/** 診断を DTO へ変換する。 */
function toDiagnostic(diagnostic: Diagnostic): JsonDiagnostic {
  return {
    level: diagnostic.level,
    message: diagnostic.message,
    ...(diagnostic.file === undefined ? {} : { file: diagnostic.file }),
    ...(diagnostic.range === undefined ? {} : { range: toRange(diagnostic.range) }),
  };
}

/** ファイル情報を DTO へ変換する。 */
function toFile(file: SourceFileInfo): JsonFile {
  return {
    path: file.path,
    relativePath: file.relativePath,
    hash: file.hash,
    lineCount: file.lineCount,
  };
}

/**
 * `AnalysisResult` をキー順固定の JSON ドキュメントへ変換する。
 *
 * @param result 解析結果。
 * @returns 2 スペースインデントの JSON 文字列（末尾改行あり）。
 */
function serialize(result: AnalysisResult): string {
  const document: JsonDocument = {
    schemaVersion: result.schemaVersion,
    tool: {
      name: result.tool.name,
      version: result.tool.version,
      engineVersion: result.tool.engineVersion,
      configOrigin: result.tool.configOrigin,
    },
    stats: {
      filesScanned: result.stats.filesScanned,
      functionsAnalysed: result.stats.functionsAnalysed,
      flowNodes: result.stats.flowNodes,
      flowEdges: result.stats.flowEdges,
      iterations: result.stats.iterations,
      truncated: [...result.stats.truncated],
    },
    findings: result.findings.map(toFinding),
    diagnostics: result.diagnostics.map(toDiagnostic),
    files: result.files.map(toFile),
  };

  return `${JSON.stringify(document, null, 2)}\n`;
}

/**
 * 機械可読 JSON レポータを生成する。
 *
 * @returns `format === 'json'` のレポータ。同じ入力に対して常に同一の文字列を返す。
 */
export function createJsonReporter(): Reporter {
  return {
    format: 'json',
    render: serialize,
  };
}
