/**
 * Pretty レポータ — 人が読むための端末出力。
 *
 * 設計方針:
 * - ANSI エスケープは `color: true` のときだけ出力する（既定 false）。
 *   色は「文字列を包む」だけで構造を変えないため、色付き出力から ANSI を除去すると
 *   色なし出力と完全に一致する（テストで固定している）。
 * - 端末幅（TTY の桁数）は一切参照しない。参照すると環境ごとに出力が変わり、
 *   レポータの再現性が壊れるため、折り返しや省略は件数ベースでだけ行う。
 * - 検出ラベル・メッセージ・パスはスキャン対象のソース由来、つまり信頼できない入力である。
 *   とくに ESC（U+001B）をそのまま流すと、細工したソースコードで端末に任意の
 *   ANSI シーケンスを注入できてしまう。端末へ出す直前に制御文字を可視表現へ置換する。
 * - 検出の並び順は入力のまま尊重する。正準順序を決めるのは解析エンジンの責務である。
 */

import type { AnalysisResult, Diagnostic, Finding, ProofStep, Reporter, Severity } from '../types.js';

/** `createPrettyReporter` のオプション。 */
export interface PrettyReporterOptions {
  /** true のときだけ ANSI エスケープを出力する（既定 false）。 */
  readonly color?: boolean;
  /** 1 検出あたりに表示する汚染経路ステップの上限（既定 12）。 */
  readonly maxProofSteps?: number;
}

/** 経路ステップの既定表示数。これを超える経路は省略記号で畳む。 */
const DEFAULT_MAX_PROOF_STEPS = 12;

/** 打ち切られた関数の表示上限。これを超えた分は件数だけを示す。 */
const MAX_TRUNCATED_SHOWN = 5;

/** サマリの罫線の長さ。TTY 幅に依存させないため固定値にする。 */
const RULE_WIDTH = 42;

/** 汚染経路の役割。表示幅を揃えるために配列で保持する。 */
const PROOF_ROLES = ['source', 'propagate', 'sanitize', 'sink'] as const;

/** 汚染経路の役割。 */
type ProofRole = (typeof PROOF_ROLES)[number];

/** 役割ラベルの表示幅（最長の役割名に合わせる）。 */
const ROLE_WIDTH = PROOF_ROLES.reduce((width, role) => Math.max(width, role.length), 0);

/** ツリーの枝（後続あり）。 */
const TREE_TEE = '├─';

/** ツリーの枝（最後）。 */
const TREE_ELBOW = '└─';

/** ツリーの縦線。 */
const TREE_PIPE = '│ ';

/** 重要度ごとの ANSI コード。 */
const SEVERITY_COLORS: Readonly<Record<Severity, string>> = {
  error: '\u001b[1;31m',
  warning: '\u001b[1;33m',
  note: '\u001b[1;36m',
};

/** 経路ステップの役割ごとの ANSI コード。 */
const ROLE_COLORS: Readonly<Record<ProofRole, string>> = {
  source: '\u001b[35m',
  propagate: '\u001b[34m',
  sanitize: '\u001b[32m',
  sink: '\u001b[1;31m',
};

/** 見出し用の ANSI コード（太字）。 */
const BOLD = '\u001b[1m';

/** 補助情報用の ANSI コード（淡色）。 */
const DIM = '\u001b[2m';

/** 正常終了を示す ANSI コード（緑）。 */
const GREEN = '\u001b[32m';

/** ANSI 属性のリセット。 */
const RESET = '\u001b[0m';

/** 解決済みのオプション。 */
interface ResolvedOptions {
  readonly color: boolean;
  readonly maxProofSteps: number;
}

/** 文字列を ANSI コードで包む関数。color が false なら素通しする。 */
type Styler = (text: string, ansi: string) => string;

/**
 * スタイラを作る。
 *
 * @param color true なら ANSI を付ける。
 * @returns 文字列を装飾する関数。false のときは恒等関数。
 */
function createStyler(color: boolean): Styler {
  if (!color) {
    return (text) => text;
  }
  return (text, ansi) => `${ansi}${text}${RESET}`;
}

/**
 * 端末へ出す前に制御文字を可視表現へ置換する（ターミナル注入対策）。
 *
 * 改行・タブは `\n` のような 2 文字表記に、ESC を含むその他の C0/C1 制御文字は
 * `\x1b` 形式にする。日本語などの非 ASCII 文字はそのまま通す。
 *
 * @param text 信頼できない可能性のある文字列。
 * @returns 制御文字を含まない 1 行相当の文字列。
 */
function sanitizeTerminalText(text: string): string {
  let out = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (char === '\n') {
      out += '\\n';
      continue;
    }
    if (char === '\r') {
      out += '\\r';
      continue;
    }
    if (char === '\t') {
      out += '\\t';
      continue;
    }
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) {
      out += `\\x${code.toString(16).padStart(2, '0')}`;
      continue;
    }
    if (code === 0x2028 || code === 0x2029) {
      out += `\\u${code.toString(16)}`;
      continue;
    }
    out += char;
  }
  return out;
}

/**
 * 端末での表示幅を数える。CJK の全角文字を 2 桁として扱い、日本語ラベルを揃える。
 *
 * @param text 対象文字列。
 * @returns 表示桁数。
 */
function displayWidth(text: string): number {
  let width = 0;
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    width += isWideCodePoint(code) ? 2 : 1;
  }
  return width;
}

/**
 * 全角幅の文字かどうかを判定する（東アジアの Wide / Fullwidth 相当）。
 *
 * @param code Unicode コードポイント。
 * @returns 表示幅 2 なら true。
 */
function isWideCodePoint(code: number): boolean {
  return (
    (code >= 0x1100 && code <= 0x115f) ||
    (code >= 0x2e80 && code <= 0xa4cf && code !== 0x303f) ||
    (code >= 0xac00 && code <= 0xd7a3) ||
    (code >= 0xf900 && code <= 0xfaff) ||
    (code >= 0xfe30 && code <= 0xfe6f) ||
    (code >= 0xff00 && code <= 0xff60) ||
    (code >= 0xffe0 && code <= 0xffe6) ||
    (code >= 0x20000 && code <= 0x3fffd)
  );
}

/**
 * 表示幅ベースで右側を空白埋めする。
 *
 * @param label ラベル文字列。
 * @param width 目標の表示幅。
 * @returns 幅を揃えたラベル。
 */
function padLabel(label: string, width: number): string {
  const padding = Math.max(0, width - displayWidth(label));
  return `${label}${' '.repeat(padding)}`;
}

/**
 * `maxProofSteps` を安全な整数へ正規化する。
 *
 * @param value 利用者が渡した値（未指定・NaN・負数もありうる）。
 * @returns 0 以上の整数。
 */
function resolveMaxProofSteps(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) {
    return DEFAULT_MAX_PROOF_STEPS;
  }
  return Math.max(0, Math.floor(value));
}

/**
 * `file`（絶対パス）と `relativePath` からプロジェクトルートを推定する。
 *
 * @param file 絶対パス。
 * @param relativePath ルート相対パス。
 * @returns 推定できたルート（末尾に区切りなし）。推定できないときは null。
 */
function inferProjectRoot(file: string, relativePath: string): string | null {
  const absolute = file.replace(/\\/g, '/');
  const relative = relativePath.replace(/\\/g, '/').replace(/^\.\//, '');
  if (relative === '') {
    return null;
  }
  if (absolute.endsWith(`/${relative}`)) {
    return absolute.slice(0, absolute.length - relative.length - 1);
  }
  return null;
}

/**
 * 経路ステップのパスを表示用に短縮する。
 *
 * @param path ステップのファイルパス。
 * @param root 推定済みプロジェクトルート（null なら短縮しない）。
 * @returns 表示用パス。
 */
function shortenPath(path: string, root: string | null): string {
  if (root === null || root === '') {
    return path;
  }
  const normalized = path.replace(/\\/g, '/');
  return normalized.startsWith(`${root}/`) ? normalized.slice(root.length + 1) : path;
}

/**
 * 検出の表示パスを組み立てる（`path:line:column`）。
 *
 * @param finding 対象の検出。
 * @returns `relativePath:line:column`。`relativePath` が空なら絶対パスを使う。
 */
function formatLocation(finding: Finding): string {
  const path = finding.relativePath === '' ? finding.file : finding.relativePath;
  return `${path}:${finding.range.start.line}:${finding.range.start.column}`;
}

/**
 * 重要度ごとの件数を数える。
 *
 * @param findings 検出の配列。
 * @returns 重要度 → 件数。
 */
function countSeverities(findings: readonly Finding[]): Readonly<Record<Severity, number>> {
  const counts: Record<Severity, number> = { error: 0, warning: 0, note: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

/**
 * 検出を含むファイルの数を数える。
 *
 * @param findings 検出の配列。
 * @returns 重複を除いたファイル数。
 */
function countAffectedFiles(findings: readonly Finding[]): number {
  const paths = new Set<string>();
  for (const finding of findings) {
    paths.add(finding.relativePath === '' ? finding.file : finding.relativePath);
  }
  return paths.size;
}

/** 経路ステップの表示の内訳。 */
interface ProofSelection {
  /** 先頭から表示するステップ。 */
  readonly head: readonly ProofStep[];
  /** 省略したステップ数。 */
  readonly omitted: number;
  /** 末尾に表示するステップ（多くの場合 sink）。 */
  readonly tail: readonly ProofStep[];
}

/**
 * 表示する経路ステップを選ぶ。source と sink は残し、中間だけを畳む。
 *
 * @param proof 汚染経路。
 * @param max 表示上限。
 * @returns 表示するステップと省略数。
 */
function selectProofSteps(proof: readonly ProofStep[], max: number): ProofSelection {
  if (max <= 0) {
    return { head: [], omitted: proof.length, tail: [] };
  }
  if (proof.length <= max) {
    return { head: proof, omitted: 0, tail: [] };
  }
  const last = proof[proof.length - 1];
  if (last === undefined) {
    return { head: [], omitted: 0, tail: [] };
  }
  if (max === 1) {
    return { head: [], omitted: proof.length - 1, tail: [last] };
  }
  return { head: proof.slice(0, max - 1), omitted: proof.length - max, tail: [last] };
}

/**
 * 経路ステップ 1 件を 1 行へ描画する。
 *
 * @param step ステップ。
 * @param connector ツリーの枝。
 * @param root 推定済みプロジェクトルート。
 * @param styler 装飾関数。
 * @returns 描画済みの行。
 */
function renderProofStep(
  step: ProofStep,
  connector: string,
  root: string | null,
  styler: Styler,
): string {
  const role = sanitizeTerminalText(step.role);
  const path = shortenPath(step.file, root).replace(/\\/g, '/');
  const location = `${sanitizeTerminalText(path)}:${step.range.start.line}:${step.range.start.column}`;
  const label = sanitizeTerminalText(step.label).trim();
  const note = step.note === undefined ? '' : ` (${sanitizeTerminalText(step.note).trim()})`;
  const tail = label === '' ? note : `  ${label}${note}`;
  return `  ${styler(connector, DIM)} ${styler(padLabel(role, ROLE_WIDTH), ROLE_COLORS[step.role])} ${location}${tail}`;
}

/**
 * 汚染経路を `├─` / `└─` のツリーとして描画する。
 *
 * @param proof 汚染経路。
 * @param finding 経路の所属検出（ルート推定に使う）。
 * @param options 解決済みオプション。
 * @param styler 装飾関数。
 * @returns 描画済みの行の配列。
 */
function renderProofTree(
  proof: readonly ProofStep[],
  finding: Finding,
  options: ResolvedOptions,
  styler: Styler,
): string[] {
  if (proof.length === 0) {
    return [`  ${styler(TREE_ELBOW, DIM)} ${styler('(経路情報なし)', DIM)}`];
  }

  const root = inferProjectRoot(finding.file, finding.relativePath);
  const selection = selectProofSteps(proof, options.maxProofSteps);
  const total = selection.head.length + (selection.omitted > 0 ? 1 : 0) + selection.tail.length;
  const lines: string[] = [];
  let index = 0;

  for (const step of selection.head) {
    index += 1;
    lines.push(renderProofStep(step, index === total ? TREE_ELBOW : TREE_TEE, root, styler));
  }
  if (selection.omitted > 0) {
    index += 1;
    const connector = index === total ? TREE_ELBOW : TREE_TEE;
    const note = styler(`… 残り ${selection.omitted} ステップを省略`, DIM);
    lines.push(`  ${styler(connector, DIM)} ${styler(TREE_PIPE, DIM)}${note}`);
  }
  for (const step of selection.tail) {
    index += 1;
    lines.push(renderProofStep(step, index === total ? TREE_ELBOW : TREE_TEE, root, styler));
  }
  return lines;
}

/**
 * 検出 1 件分のブロックを描画する。
 *
 * @param finding 検出。
 * @param options 解決済みオプション。
 * @param styler 装飾関数。
 * @returns 描画済みの行の配列。
 */
function renderFinding(finding: Finding, options: ResolvedOptions, styler: Styler): string[] {
  const lines: string[] = [];
  const severity = styler(`[${finding.severity}]`, SEVERITY_COLORS[finding.severity]);
  const rule = styler(sanitizeTerminalText(finding.ruleId), BOLD);
  const location = styler(sanitizeTerminalText(formatLocation(finding)), DIM);
  lines.push(`${severity} ${rule}  ${location}`);

  const message = sanitizeTerminalText(finding.message).trim();
  if (message !== '') {
    lines.push(`  ${message}`);
  }
  if (finding.cwe !== undefined && finding.cwe.length > 0) {
    const cwes = finding.cwe.map((cwe) => sanitizeTerminalText(cwe)).join(', ');
    lines.push(`  ${styler('cwe:', DIM)} ${cwes}`);
  }
  if (finding.advice !== undefined) {
    const advice = sanitizeTerminalText(finding.advice).trim();
    if (advice !== '') {
      lines.push(`  ${styler('advice:', DIM)} ${advice}`);
    }
  }

  lines.push(...renderProofTree(finding.proof, finding, options, styler));
  return lines;
}

/**
 * 診断（回復可能な問題）のブロックを描画する。
 *
 * @param diagnostics 診断の配列。
 * @param styler 装飾関数。
 * @returns 描画済みの行の配列。
 */
function renderDiagnostics(diagnostics: readonly Diagnostic[], styler: Styler): string[] {
  const lines: string[] = [`${styler(`診断 ${diagnostics.length} 件:`, BOLD)}`];
  for (const diagnostic of diagnostics) {
    const level = styler(`[${diagnostic.level}]`, DIM);
    const position =
      diagnostic.file === undefined
        ? ''
        : ` ${sanitizeTerminalText(diagnostic.file)}${
            diagnostic.range === undefined
              ? ''
              : `:${diagnostic.range.start.line}:${diagnostic.range.start.column}`
          }`;
    lines.push(`  ${level}${position} ${sanitizeTerminalText(diagnostic.message)}`);
  }
  return lines;
}

/**
 * 末尾のサマリブロックを描画する。
 *
 * @param result 解析結果。
 * @param styler 装飾関数。
 * @returns 描画済みの行の配列。
 */
function renderSummary(result: AnalysisResult, styler: Styler): string[] {
  const counts = countSeverities(result.findings);
  const stats = result.stats;
  const label = (text: string): string => styler(padLabel(text, 10), DIM);
  const lines: string[] = [
    styler(`── サマリ ${'─'.repeat(RULE_WIDTH)}`, DIM),
    `${label('検出')}: ${result.findings.length} 件（error ${counts.error} / warning ${counts.warning} / note ${counts.note}）`,
    `${label('ファイル')}: ${stats.filesScanned} 件をスキャン、${countAffectedFiles(result.findings)} 件で検出`,
    `${label('関数')}: ${stats.functionsAnalysed} 件を解析（iterations ${stats.iterations}）`,
    `${label('グラフ')}: ノード ${stats.flowNodes} / エッジ ${stats.flowEdges}`,
  ];

  if (result.diagnostics.length > 0) {
    const diagnosticCounts: Record<Diagnostic['level'], number> = { info: 0, warning: 0, error: 0 };
    for (const diagnostic of result.diagnostics) {
      diagnosticCounts[diagnostic.level] += 1;
    }
    lines.push(
      `${label('診断')}: info ${diagnosticCounts.info} / warning ${diagnosticCounts.warning} / error ${diagnosticCounts.error}`,
    );
  }

  if (stats.truncated.length > 0) {
    const shown = stats.truncated
      .slice(0, MAX_TRUNCATED_SHOWN)
      .map((id) => sanitizeTerminalText(id))
      .join(', ');
    const rest =
      stats.truncated.length > MAX_TRUNCATED_SHOWN
        ? ` ほか ${stats.truncated.length - MAX_TRUNCATED_SHOWN} 件`
        : '';
    lines.push(`${label('打ち切り')}: ${shown}${rest}`);
  }

  return lines;
}

/**
 * 検出ゼロのときの 1 行を描画する。
 *
 * @param result 解析結果。
 * @param styler 装飾関数。
 * @returns 改行を含む 1 行。
 */
function renderEmpty(result: AnalysisResult, styler: Styler): string {
  const stats = result.stats;
  const diagnostics =
    result.diagnostics.length === 0 ? '' : `、診断 ${result.diagnostics.length} 件`;
  const text = `検出なし — ${stats.filesScanned} ファイル / ${stats.functionsAnalysed} 関数を解析（iterations ${stats.iterations}${diagnostics}）`;
  return `${styler(text, GREEN)}\n`;
}

/**
 * 解析結果を端末向けの文字列へ変換する。
 *
 * @param result 解析結果。
 * @param options 解決済みオプション。
 * @returns 末尾に改行を含む描画結果。
 */
function renderPretty(result: AnalysisResult, options: ResolvedOptions): string {
  const styler = createStyler(options.color);
  if (result.findings.length === 0) {
    return renderEmpty(result, styler);
  }

  const counts = countSeverities(result.findings);
  const header = `${result.tool.name} ${result.tool.version} — 検出 ${result.findings.length} 件（error ${counts.error} / warning ${counts.warning} / note ${counts.note}）`;
  const blocks: string[] = [styler(header, BOLD), ''];

  for (const finding of result.findings) {
    blocks.push(...renderFinding(finding, options, styler));
    blocks.push('');
  }
  if (result.diagnostics.length > 0) {
    blocks.push(...renderDiagnostics(result.diagnostics, styler));
    blocks.push('');
  }
  blocks.push(...renderSummary(result, styler));

  return `${blocks.join('\n')}\n`;
}

/**
 * 人が読む端末出力レポータを生成する。
 *
 * @param options `color` で ANSI 出力を有効化、`maxProofSteps` で経路の表示数を制限する。
 * @returns `format === 'pretty'` のレポータ。
 */
export function createPrettyReporter(options?: PrettyReporterOptions): Reporter {
  const resolved: ResolvedOptions = {
    color: options?.color === true,
    maxProofSteps: resolveMaxProofSteps(options?.maxProofSteps),
  };
  return {
    format: 'pretty',
    render: (result) => renderPretty(result, resolved),
  };
}
