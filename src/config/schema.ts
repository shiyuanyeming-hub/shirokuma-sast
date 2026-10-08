/**
 * 設定スキーマ — 依存なしの YAML サブセットパーサと、パス付きの検証器。
 *
 * ## YAML サブセットが対応する構文
 * - トップレベルのマップ、ネストしたマップ（インデントはスペースのみ。タブはエラー）
 * - マップのシーケンス（`- key: value` と、その継続行）
 * - スカラー（プレイン / シングルクォート / ダブルクォート / 真偽値 / null / 数値）
 * - フローコレクション（`[a, b]` / `{ a: b }`。1 行に収まるもの）
 * - ブロックスカラー（`|` / `>` と chomping 指示子 `-` / `+`）
 * - コメント（`#`。クォート内とインデント内は除外）、`---` / `...` ドキュメント区切り
 *
 * YAML 1.2 core スキーマに合わせ、`yes` / `no` / `on` / `off` は真偽値ではなく文字列として扱う。
 *
 * ## 検証方針
 * 構文エラーも型不一致も `ConfigError` を投げ、`path` に `rules.sinks[2].severity` のような
 * 位置を入れる。未知のキーは警告に落として解析を続行する（前方互換）。
 * 各正規化関数は `unknown` を受け取り、実行時の値を型付きの構造へ変換する
 * （設定ファイル由来の値も、API から直接渡された値も同じ経路で検証するため）。
 */
import type {
  AnalysisConfig,
  OutputConfig,
  PatternSpec,
  SanitizerSpec,
  SinkSpec,
  SourceSpec,
  Severity,
} from '../types.js';
import { ConfigError } from './contract.js';
import { DEFAULT_ANALYSIS } from '../rules/builtin.js';

// ---------------------------------------------------------------------------
// 公開型
// ---------------------------------------------------------------------------

/** 警告の通知先。`path` は `rules.sinks[0].severity` のような位置。 */
export type WarningSink = (message: string, path: string) => void;

/** 検証済みのルール定義。`ignorePaths` は未指定と空配列を区別するため optional のまま残す。 */
export interface ValidatedRules {
  readonly sources: readonly SourceSpec[];
  readonly sanitizers: readonly SanitizerSpec[];
  readonly sinks: readonly SinkSpec[];
  readonly propagators: readonly PatternSpec[];
  readonly ignorePaths?: readonly string[];
}

/** 検証済みの設定ドキュメント。 */
export interface ValidatedDocument {
  /** `version` / `schemaVersion` が指定されていれば 1。 */
  readonly schemaVersion?: 1;
  readonly rules: ValidatedRules;
  readonly analysis?: AnalysisConfig;
  readonly output?: OutputConfig;
}

/** 正規化関数へ渡すオプション。 */
export interface NormalizeOptions {
  /** 未知キーの警告先。 */
  readonly onWarning?: WarningSink;
}

// ---------------------------------------------------------------------------
// 汎用の型チェック
// ---------------------------------------------------------------------------

/** `Record<string, unknown>` かどうか（配列・null を除く）。 */
export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** 値の種類を日本語で説明する（エラーメッセージ用）。 */
function describeValue(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return '配列';
  if (typeof value === 'string') return `文字列 "${value}"`;
  if (typeof value === 'number' || typeof value === 'boolean') return `${typeof value} ${String(value)}`;
  if (typeof value === 'object') return 'マップ';
  return typeof value;
}

/** マップであることを要求する。 */
export function expectRecord(value: unknown, path: string): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new ConfigError(`${path} はマップである必要があります（実際: ${describeValue(value)}）`, path);
  }
  return value;
}

/** 空でない文字列であることを要求する。 */
export function expectString(value: unknown, path: string): string {
  if (typeof value !== 'string') {
    throw new ConfigError(`${path} は文字列である必要があります（実際: ${describeValue(value)}）`, path);
  }
  if (value.trim() === '') {
    throw new ConfigError(`${path} は空でない文字列である必要があります`, path);
  }
  return value;
}

/** 文字列の配列であることを要求する。`allowEmpty` が false のときは空配列を拒否する。 */
export function expectStringArray(value: unknown, path: string, allowEmpty: boolean): string[] {
  if (!Array.isArray(value)) {
    throw new ConfigError(`${path} は配列である必要があります（実際: ${describeValue(value)}）`, path);
  }
  const items = value.map((item, index) => expectString(item, `${path}[${index}]`));
  if (!allowEmpty && items.length === 0) {
    throw new ConfigError(`${path} には 1 つ以上の要素が必要です`, path);
  }
  return items;
}

/** 真偽値であることを要求する。 */
export function expectBoolean(value: unknown, path: string): boolean {
  if (typeof value !== 'boolean') {
    throw new ConfigError(`${path} は true / false である必要があります（実際: ${describeValue(value)}）`, path);
  }
  return value;
}

/** 1 以上の整数であることを要求する。 */
export function expectPositiveInt(value: unknown, path: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new ConfigError(`${path} は整数である必要があります（実際: ${describeValue(value)}）`, path);
  }
  if (value <= 0) {
    throw new ConfigError(`${path} は 1 以上である必要があります（実際: ${String(value)}）`, path);
  }
  return value;
}

/** 列挙値であることを要求する。 */
export function expectEnum<T extends string>(value: unknown, allowed: readonly T[], path: string): T {
  if (typeof value === 'string') {
    for (const item of allowed) {
      if (item === value) return item;
    }
  }
  throw new ConfigError(
    `${path} は ${allowed.map((item) => `"${item}"`).join(' / ')} のいずれかである必要があります（実際: ${describeValue(value)}）`,
    path,
  );
}

/** 未知のキーを警告する。 */
function warnUnknownKeys(record: Record<string, unknown>, known: readonly string[], path: string, onWarning: WarningSink | undefined): void {
  if (onWarning === undefined) return;
  for (const key of Object.keys(record)) {
    if (known.includes(key)) continue;
    onWarning(`未知のキー "${key}" を無視しました`, path === '' ? key : `${path}.${key}`);
  }
}

// ---------------------------------------------------------------------------
// YAML サブセットパーサ
// ---------------------------------------------------------------------------

/** 1 行分の情報。`raw` はインデントを除いた内容（末尾空白は除去済み）。 */
interface SourceLine {
  readonly lineNumber: number;
  readonly indent: number;
  readonly raw: string;
}

/** パーサの状態。 */
interface ParseContext {
  readonly lines: SourceLine[];
  index: number;
  readonly sourceLabel: string;
}

/** 数値スカラー。 */
const NUMBER_PATTERN = /^[+-]?(?:\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\.\d+)$/;

/** 構文エラーを作る。 */
function yamlError(context: ParseContext, line: number, message: string, hint?: string): ConfigError {
  const location = `${context.sourceLabel}:${line}`;
  return new ConfigError(`${message}（${location} 行目）`, location, hint);
}

/** 行をインデントと内容に分解する。タブインデントはエラー。 */
function splitSourceLines(text: string, sourceLabel: string): SourceLine[] {
  const lines: SourceLine[] = [];
  const rawLines = text.split(/\r?\n/);
  for (let i = 0; i < rawLines.length; i += 1) {
    const raw = rawLines[i] ?? '';
    let indent = 0;
    while (indent < raw.length && raw.charAt(indent) === ' ') indent += 1;
    if (raw.charAt(indent) === '\t') {
      throw new ConfigError(
        'インデントにタブ文字は使えません（スペースを使用してください）',
        `${sourceLabel}:${i + 1}`,
      );
    }
    lines.push({ lineNumber: i + 1, indent, raw: raw.slice(indent).trimEnd() });
  }
  return lines;
}

/** クォートを考慮して行末コメントを除去する。 */
function stripComment(raw: string): string {
  let quote: string | undefined;
  for (let i = 0; i < raw.length; i += 1) {
    const ch = raw.charAt(i);
    if (quote !== undefined) {
      if (ch === '\\' && quote === '"') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === '#' && (i === 0 || /\s/.test(raw.charAt(i - 1)))) return raw.slice(0, i);
  }
  return raw;
}

/** 有意な行（空行・コメント・ドキュメント区切り以外）かどうか。 */
function isSignificant(line: SourceLine): boolean {
  const content = stripComment(line.raw).trim();
  return content !== '' && content !== '---' && content !== '...';
}

/** 有意な行まで進める。 */
function skipInsignificant(context: ParseContext): void {
  while (context.index < context.lines.length) {
    const line = context.lines[context.index];
    if (line === undefined || isSignificant(line)) return;
    context.index += 1;
  }
}

/** シーケンス要素の行かどうか。 */
function isSequenceLine(content: string): boolean {
  return content === '-' || content.startsWith('- ');
}

/**
 * YAML サブセットを解析してプレーンな JS 値（マップ / 配列 / スカラー）を返す。
 *
 * 構文エラーは `ConfigError`（`path` は `<sourceLabel>:<行>`）として投げる。
 */
export function parseYaml(text: string, sourceLabel = '<yaml>'): unknown {
  const context: ParseContext = { lines: splitSourceLines(text, sourceLabel), index: 0, sourceLabel };
  skipInsignificant(context);
  const first = context.lines[context.index];
  if (first === undefined) return {};
  const value = parseBlock(context, first.indent);
  skipInsignificant(context);
  const leftover = context.lines[context.index];
  if (leftover !== undefined) {
    throw yamlError(context, leftover.lineNumber, '解釈できない行が残っています（インデントを確認してください）');
  }
  return value;
}

/** 指定インデントのブロック（マップまたはシーケンス）を解析する。 */
function parseBlock(context: ParseContext, indent: number): unknown {
  skipInsignificant(context);
  const line = context.lines[context.index];
  if (line === undefined || line.indent < indent) return null;
  if (line.indent > indent) {
    throw yamlError(context, line.lineNumber, 'インデントが深すぎます（直前のキーと揃えてください）');
  }
  const content = stripComment(line.raw).trimEnd();
  if (isSequenceLine(content)) return parseSequence(context, indent);
  return parseMapping(context, indent);
}

/** マップを解析する。 */
function parseMapping(context: ParseContext, indent: number): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (;;) {
    skipInsignificant(context);
    const line = context.lines[context.index];
    if (line === undefined || line.indent < indent) break;
    if (line.indent > indent) {
      throw yamlError(context, line.lineNumber, 'インデントが不正です（キーの位置を揃えてください）');
    }
    const content = stripComment(line.raw).trimEnd();
    if (isSequenceLine(content)) {
      throw yamlError(context, line.lineNumber, 'マップの中にシーケンス要素が現れました（インデントを確認してください）');
    }
    const separator = findKeySeparator(content);
    if (separator === -1) {
      throw yamlError(context, line.lineNumber, 'キーと値の区切り ":" がありません', '例: `severity: error`');
    }
    const keyText = content.slice(0, separator).trim();
    if (keyText === '') {
      throw yamlError(context, line.lineNumber, 'キーが空です');
    }
    const key = parseKeyText(keyText, context, line);
    const rest = content.slice(separator + 1).trim();
    context.index += 1;
    let value: unknown;
    if (rest === '') value = parseChildBlock(context, indent, true);
    else if (rest.startsWith('|') || rest.startsWith('>')) value = parseBlockScalar(context, indent, rest);
    else value = parseInlineValue(context, rest, line, indent);
    if (Object.prototype.hasOwnProperty.call(result, key)) {
      throw yamlError(context, line.lineNumber, `キー "${key}" が重複しています`);
    }
    result[key] = value;
  }
  return result;
}

/** シーケンスを解析する。 */
function parseSequence(context: ParseContext, indent: number): unknown[] {
  const items: unknown[] = [];
  for (;;) {
    skipInsignificant(context);
    const line = context.lines[context.index];
    if (line === undefined) break;
    if (line.indent < indent) break;
    if (line.indent > indent) {
      throw yamlError(context, line.lineNumber, 'シーケンス要素のインデントが不正です');
    }
    const content = stripComment(line.raw).trimEnd();
    if (!isSequenceLine(content)) break;
    if (content === '-') {
      context.index += 1;
      items.push(parseChildBlock(context, indent));
      continue;
    }
    const afterDash = content.slice(1);
    const offset = content.length - afterDash.trimStart().length;
    const itemText = afterDash.trim();
    const flowLike = itemText.startsWith('[') || itemText.startsWith('{');
    if (itemText !== '' && findKeySeparator(itemText) !== -1 && !flowLike) {
      // `- key: value` 形式。行を「ダッシュの位置 + オフセット」の仮想行へ置き換えてマップとして解析する。
      context.lines[context.index] = { lineNumber: line.lineNumber, indent: indent + offset, raw: afterDash.trimStart() };
      items.push(parseMapping(context, indent + offset));
      continue;
    }
    if (isSequenceLine(itemText)) {
      // `- - a` のようなネストしたシーケンス。
      context.lines[context.index] = { lineNumber: line.lineNumber, indent: indent + offset, raw: afterDash.trimStart() };
      items.push(parseSequence(context, indent + offset));
      continue;
    }
    context.index += 1;
    if (itemText === '') {
      items.push(parseChildBlock(context, indent));
      continue;
    }
    items.push(parseInlineValue(context, itemText, line, indent));
  }
  return items;
}

/**
 * `key:` の直後にある子ブロックを解析する。子が無ければ null。
 *
 * `allowSameIndentSequence` は `key:\n- a\n- b` のようにシーケンスがキーと同じ
 * インデントで書かれた場合を許すかどうか（マップの値のときだけ許される）。
 */
function parseChildBlock(context: ParseContext, parentIndent: number, allowSameIndentSequence = false): unknown {
  skipInsignificant(context);
  const line = context.lines[context.index];
  if (line === undefined) return null;
  if (line.indent > parentIndent) return parseBlock(context, line.indent);
  if (allowSameIndentSequence && line.indent === parentIndent && isSequenceLine(stripComment(line.raw).trimEnd())) {
    return parseSequence(context, parentIndent);
  }
  return null;
}

/** インライン値（フローコレクション / ブロックスカラー / スカラー）を解析する。 */
function parseInlineValue(context: ParseContext, text: string, line: SourceLine, indent: number): unknown {
  if (text.startsWith('[') || text.startsWith('{')) return parseFlow(context, text, line);
  if (text.startsWith('|') || text.startsWith('>')) return parseBlockScalar(context, indent, text);
  return parseScalarText(context, text, line);
}

/** キー文字列を解析する（クォート解除のみ）。 */
function parseKeyText(text: string, context: ParseContext, line: SourceLine): string {
  const value = parseScalarText(context, text, line);
  if (typeof value === 'string') return value;
  if (value === null) throw yamlError(context, line.lineNumber, 'キーが空です');
  return String(value);
}

/**
 * キーと値の区切り `:` の位置を返す。クォート内・フロー括弧内・`::` は対象外。
 * YAML の規則どおり、`:` の直後が空白か行末のときだけ区切りとして扱う。
 */
function findKeySeparator(content: string): number {
  let quote: string | undefined;
  let depth = 0;
  for (let i = 0; i < content.length; i += 1) {
    const ch = content.charAt(i);
    if (quote !== undefined) {
      if (ch === '\\' && quote === '"') {
        i += 1;
        continue;
      }
      if (ch === quote) quote = undefined;
      continue;
    }
    if (ch === "'" || ch === '"') {
      quote = ch;
      continue;
    }
    if (ch === '[' || ch === '{') {
      depth += 1;
      continue;
    }
    if (ch === ']' || ch === '}') {
      depth -= 1;
      continue;
    }
    if (ch === ':' && depth === 0) {
      const next = content.charAt(i + 1);
      if (next === '' || next === ' ' || next === '\t') return i;
    }
  }
  return -1;
}

/** プレイン / クォート済みスカラーを解析する。 */
function parseScalarText(context: ParseContext, text: string, line: SourceLine): unknown {
  const value = text.trim();
  if (value === '' || value === '~' || value === 'null' || value === 'Null' || value === 'NULL') return null;
  if (value === 'true' || value === 'True' || value === 'TRUE') return true;
  if (value === 'false' || value === 'False' || value === 'FALSE') return false;
  if (NUMBER_PATTERN.test(value)) return Number(value);
  if (value.startsWith("'")) return decodeSingleQuoted(context, value, line);
  if (value.startsWith('"')) return decodeDoubleQuoted(context, value, line);
  return value;
}

/** シングルクォート文字列をデコードする（`''` は `'`）。 */
function decodeSingleQuoted(context: ParseContext, text: string, line: SourceLine): string {
  if (text.length < 2 || !text.endsWith("'")) {
    throw yamlError(context, line.lineNumber, 'シングルクォート文字列が閉じられていません');
  }
  return text.slice(1, -1).replace(/''/g, "'");
}

/** ダブルクォート文字列をデコードする（`\n` / `\t` / `\uXXXX` など）。 */
function decodeDoubleQuoted(context: ParseContext, text: string, line: SourceLine): string {
  if (text.length < 2 || !text.endsWith('"')) {
    throw yamlError(context, line.lineNumber, 'ダブルクォート文字列が閉じられていません');
  }
  let result = '';
  let i = 1;
  while (i < text.length - 1) {
    const ch = text.charAt(i);
    if (ch !== '\\') {
      result += ch;
      i += 1;
      continue;
    }
    const escaped = text.charAt(i + 1);
    switch (escaped) {
      case 'n':
        result += '\n';
        break;
      case 't':
        result += '\t';
        break;
      case 'r':
        result += '\r';
        break;
      case '0':
        result += '\0';
        break;
      case '"':
        result += '"';
        break;
      case '\\':
        result += '\\';
        break;
      case '/':
        result += '/';
        break;
      case 'u': {
        const hex = text.slice(i + 2, i + 6);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
          throw yamlError(context, line.lineNumber, '\\u エスケープは 4 桁の 16 進数である必要があります');
        }
        result += String.fromCharCode(Number.parseInt(hex, 16));
        i += 4;
        break;
      }
      default:
        result += escaped;
        break;
    }
    i += 2;
  }
  return result;
}

/** ブロックスカラー（`|` / `>`）を解析する。 */
function parseBlockScalar(context: ParseContext, parentIndent: number, header: string): string {
  const indicator = header.charAt(0);
  const modifiers = header.slice(1).trim();
  const chomp = modifiers.includes('-') ? '-' : modifiers.includes('+') ? '+' : '';
  const collected: string[] = [];
  while (context.index < context.lines.length) {
    const line = context.lines[context.index];
    if (line === undefined) break;
    if (line.raw.trim() === '') {
      collected.push('');
      context.index += 1;
      continue;
    }
    if (line.indent <= parentIndent) break;
    collected.push(' '.repeat(line.indent) + line.raw);
    context.index += 1;
  }
  while (collected.length > 0 && (collected[collected.length - 1] ?? '').trim() === '') collected.pop();
  const contentIndent = collected.reduce((minimum, raw) => {
    if (raw.trim() === '') return minimum;
    const indent = raw.length - raw.trimStart().length;
    return minimum === -1 || indent < minimum ? indent : minimum;
  }, -1);
  const lines = collected.map((raw) => (raw.trim() === '' ? '' : raw.slice(contentIndent === -1 ? 0 : contentIndent)));
  const body = indicator === '>' ? foldLines(lines) : lines.join('\n');
  if (chomp === '-') return body.replace(/\n+$/, '');
  if (chomp === '+') return body === '' ? '' : `${body}\n`;
  const trimmed = body.replace(/\n+$/, '');
  return trimmed === '' ? '' : `${trimmed}\n`;
}

/** 折り返しブロックスカラー（`>`）の行を結合する。 */
function foldLines(lines: readonly string[]): string {
  let result = '';
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i] ?? '';
    if (line === '') {
      result += '\n';
      continue;
    }
    result += i === 0 || result.endsWith('\n') ? line : ` ${line}`;
  }
  return result;
}

/** フローコレクション（`[...]` / `{...}`）を解析する。 */
function parseFlow(context: ParseContext, text: string, line: SourceLine): unknown {
  const state = { text, position: 0 };
  const value = parseFlowValue(context, state, line);
  skipFlowWhitespace(state);
  if (state.position < state.text.length) {
    throw yamlError(context, line.lineNumber, `フローコレクションの後に余分な文字があります: "${state.text.slice(state.position)}"`);
  }
  return value;
}

/** フロー解析の状態。 */
interface FlowState {
  readonly text: string;
  position: number;
}

/** 空白を読み飛ばす。 */
function skipFlowWhitespace(state: FlowState): void {
  while (state.position < state.text.length && /\s/.test(state.text.charAt(state.position))) {
    state.position += 1;
  }
}

/** フローの 1 値を解析する。 */
function parseFlowValue(context: ParseContext, state: FlowState, line: SourceLine): unknown {
  skipFlowWhitespace(state);
  const ch = state.text.charAt(state.position);
  if (ch === '[') {
    state.position += 1;
    const items: unknown[] = [];
    skipFlowWhitespace(state);
    if (state.text.charAt(state.position) === ']') {
      state.position += 1;
      return items;
    }
    for (;;) {
      items.push(parseFlowValue(context, state, line));
      skipFlowWhitespace(state);
      const next = state.text.charAt(state.position);
      if (next === ',') {
        state.position += 1;
        continue;
      }
      if (next === ']') {
        state.position += 1;
        return items;
      }
      throw yamlError(context, line.lineNumber, 'フローシーケンスは "," または "]" で区切ってください');
    }
  }
  if (ch === '{') {
    state.position += 1;
    const result: Record<string, unknown> = {};
    skipFlowWhitespace(state);
    if (state.text.charAt(state.position) === '}') {
      state.position += 1;
      return result;
    }
    for (;;) {
      skipFlowWhitespace(state);
      const key = parseFlowKey(context, state, line);
      skipFlowWhitespace(state);
      let value: unknown = null;
      if (state.text.charAt(state.position) === ':') {
        state.position += 1;
        value = parseFlowValue(context, state, line);
      }
      result[key] = value;
      skipFlowWhitespace(state);
      const next = state.text.charAt(state.position);
      if (next === ',') {
        state.position += 1;
        continue;
      }
      if (next === '}') {
        state.position += 1;
        return result;
      }
      throw yamlError(context, line.lineNumber, 'フローマップは "," または "}" で区切ってください');
    }
  }
  return parseFlowScalar(context, state, line);
}

/** フローマップのキーを読む。 */
function parseFlowKey(context: ParseContext, state: FlowState, line: SourceLine): string {
  const ch = state.text.charAt(state.position);
  if (ch === "'" || ch === '"') {
    const value = parseFlowScalar(context, state, line);
    return typeof value === 'string' ? value : String(value);
  }
  const start = state.position;
  while (state.position < state.text.length) {
    const current = state.text.charAt(state.position);
    if (current === ':' || current === ',' || current === '}') break;
    state.position += 1;
  }
  const key = state.text.slice(start, state.position).trim();
  if (key === '') throw yamlError(context, line.lineNumber, 'フローマップのキーが空です');
  return key;
}

/** フローのスカラーを読む（`,` / `]` / `}` まで）。 */
function parseFlowScalar(context: ParseContext, state: FlowState, line: SourceLine): unknown {
  const ch = state.text.charAt(state.position);
  if (ch === "'" || ch === '"') {
    const start = state.position;
    state.position += 1;
    while (state.position < state.text.length) {
      const current = state.text.charAt(state.position);
      if (current === '\\' && ch === '"') {
        state.position += 2;
        continue;
      }
      if (current === ch) {
        state.position += 1;
        break;
      }
      state.position += 1;
    }
    return parseScalarText(context, state.text.slice(start, state.position), line);
  }
  const start = state.position;
  while (state.position < state.text.length) {
    const current = state.text.charAt(state.position);
    if (current === ',' || current === ']' || current === '}') break;
    state.position += 1;
  }
  return parseScalarText(context, state.text.slice(start, state.position), line);
}

// ---------------------------------------------------------------------------
// ルール定義の正規化
// ---------------------------------------------------------------------------

/** パターン（`member` / `identifier` / `call`）を読み取る。1 つも無ければエラー。 */
function readPattern(record: Record<string, unknown>, path: string): { member?: string; identifier?: string; call?: string } {
  const member = record['member'] === undefined ? undefined : expectString(record['member'], `${path}.member`);
  const identifier = record['identifier'] === undefined ? undefined : expectString(record['identifier'], `${path}.identifier`);
  const call = record['call'] === undefined ? undefined : expectString(record['call'], `${path}.call`);
  if (member !== undefined && /[\s()[\]{}]/.test(member)) {
    throw new ConfigError(
      `${path}.member は "db.query" のようなドット区切りの式で指定してください（実際: "${member}"）`,
      `${path}.member`,
    );
  }
  if (identifier !== undefined && !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(identifier)) {
    throw new ConfigError(`${path}.identifier は単純な識別子である必要があります（実際: "${identifier}"）`, `${path}.identifier`);
  }
  if (call !== undefined && !/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(call)) {
    throw new ConfigError(`${path}.call は単純な関数名である必要があります（実際: "${call}"）`, `${path}.call`);
  }
  if (member === undefined && identifier === undefined && call === undefined) {
    throw new ConfigError(
      `${path} には member / identifier / call のいずれか 1 つ以上が必要です`,
      path,
      '例: `member: "child_process.exec"`',
    );
  }
  return {
    ...(member !== undefined ? { member } : {}),
    ...(identifier !== undefined ? { identifier } : {}),
    ...(call !== undefined ? { call } : {}),
  };
}

/** ソース定義を正規化する。 */
export function normalizeSourceSpec(value: unknown, path: string, options: NormalizeOptions = {}): SourceSpec {
  const record = expectRecord(value, path);
  warnUnknownKeys(record, ['id', 'kinds', 'member', 'identifier', 'call', 'withinFunctions', 'description'], path, options.onWarning);
  const id = expectString(record['id'], `${path}.id`);
  const kinds = expectStringArray(record['kinds'], `${path}.kinds`, false);
  const pattern = readPattern(record, path);
  const withinFunctions = record['withinFunctions'] === undefined ? undefined : expectStringArray(record['withinFunctions'], `${path}.withinFunctions`, false);
  const description = record['description'] === undefined ? undefined : expectString(record['description'], `${path}.description`);
  return {
    id,
    kinds,
    ...pattern,
    ...(withinFunctions !== undefined ? { withinFunctions } : {}),
    ...(description !== undefined ? { description } : {}),
  };
}

/** サニタイザ定義を正規化する。`kinds` は省略可（空配列＝すべてのタグ）。 */
export function normalizeSanitizerSpec(value: unknown, path: string, options: NormalizeOptions = {}): SanitizerSpec {
  const record = expectRecord(value, path);
  warnUnknownKeys(record, ['id', 'member', 'identifier', 'call', 'kinds', 'validation', 'description'], path, options.onWarning);
  const id = expectString(record['id'], `${path}.id`);
  const pattern = readPattern(record, path);
  const kinds = record['kinds'] === undefined ? [] : expectStringArray(record['kinds'], `${path}.kinds`, true);
  const validation = record['validation'] === undefined ? 'none' : expectEnum(record['validation'], ['static-sql', 'constant-argument', 'none'] as const, `${path}.validation`);
  const description = record['description'] === undefined ? undefined : expectString(record['description'], `${path}.description`);
  return {
    id,
    ...pattern,
    kinds,
    validation,
    ...(description !== undefined ? { description } : {}),
  };
}

/** シンク定義を正規化する。 */
export function normalizeSinkSpec(value: unknown, path: string, options: NormalizeOptions = {}): SinkSpec {
  const record = expectRecord(value, path);
  warnUnknownKeys(record, ['id', 'member', 'identifier', 'call', 'kinds', 'severity', 'taintedArgs', 'cwe', 'message', 'advice'], path, options.onWarning);
  const id = expectString(record['id'], `${path}.id`);
  const pattern = readPattern(record, path);
  const kinds = expectStringArray(record['kinds'], `${path}.kinds`, false);
  const severity: Severity = expectEnum(record['severity'], ['error', 'warning', 'note'] as const, `${path}.severity`);
  const message = expectString(record['message'], `${path}.message`);
  const advice = record['advice'] === undefined ? undefined : expectString(record['advice'], `${path}.advice`);
  const taintedArgs = record['taintedArgs'] === undefined ? undefined : normalizeTaintedArgs(record['taintedArgs'], `${path}.taintedArgs`);
  const cwe = record['cwe'] === undefined ? undefined : expectStringArray(record['cwe'], `${path}.cwe`, false);
  return {
    id,
    ...pattern,
    kinds,
    severity,
    message,
    ...(taintedArgs !== undefined ? { taintedArgs } : {}),
    ...(cwe !== undefined ? { cwe } : {}),
    ...(advice !== undefined ? { advice } : {}),
  };
}

/** `taintedArgs`（0 以上の整数の配列）を検証する。 */
function normalizeTaintedArgs(value: unknown, path: string): number[] {
  if (!Array.isArray(value)) {
    throw new ConfigError(`${path} は配列である必要があります（実際: ${describeValue(value)}）`, path);
  }
  return value.map((item, index) => {
    if (typeof item !== 'number' || !Number.isInteger(item) || item < 0) {
      throw new ConfigError(`${path}[${index}] は 0 以上の整数である必要があります（実際: ${describeValue(item)}）`, `${path}[${index}]`);
    }
    return item;
  });
}

/** 伝播規則を正規化する。 */
export function normalizePropagator(value: unknown, path: string, options: NormalizeOptions = {}): PatternSpec {
  const record = expectRecord(value, path);
  warnUnknownKeys(record, ['member', 'identifier', 'call', 'allowDynamic'], path, options.onWarning);
  const pattern = readPattern(record, path);
  const allowDynamic = record['allowDynamic'] === undefined ? undefined : expectBoolean(record['allowDynamic'], `${path}.allowDynamic`);
  return { ...pattern, ...(allowDynamic !== undefined ? { allowDynamic } : {}) };
}

/** 解析設定を正規化する。 */
export function normalizeAnalysisConfig(value: unknown, path = 'analysis', options: NormalizeOptions = {}): AnalysisConfig {
  const record = expectRecord(value, path);
  warnUnknownKeys(record, ['maxCallDepth', 'maxIterations', 'kinds', 'dedupe'], path, options.onWarning);
  const maxCallDepth = record['maxCallDepth'] === undefined ? undefined : expectPositiveInt(record['maxCallDepth'], `${path}.maxCallDepth`);
  const maxIterations = record['maxIterations'] === undefined ? undefined : expectPositiveInt(record['maxIterations'], `${path}.maxIterations`);
  const kinds = record['kinds'] === undefined ? undefined : expectStringArray(record['kinds'], `${path}.kinds`, true);
  const dedupe = record['dedupe'] === undefined ? undefined : expectBoolean(record['dedupe'], `${path}.dedupe`);
  return {
    maxCallDepth: maxCallDepth ?? DEFAULT_ANALYSIS.maxCallDepth,
    maxIterations: maxIterations ?? DEFAULT_ANALYSIS.maxIterations,
    ...(kinds !== undefined ? { kinds } : {}),
    ...(dedupe !== undefined ? { dedupe } : {}),
  };
}

/** 出力設定を正規化する。 */
export function normalizeOutputConfig(value: unknown, path = 'output', options: NormalizeOptions = {}): OutputConfig {
  const record = expectRecord(value, path);
  warnUnknownKeys(record, ['format', 'output', 'failOn'], path, options.onWarning);
  const format = record['format'] === undefined ? undefined : expectEnum(record['format'], ['pretty', 'json', 'sarif', 'markdown'] as const, `${path}.format`);
  const output = record['output'] === undefined ? undefined : expectString(record['output'], `${path}.output`);
  const failOn = record['failOn'] === undefined ? undefined : expectEnum(record['failOn'], ['error', 'warning', 'note', 'none'] as const, `${path}.failOn`);
  if (format === undefined) {
    throw new ConfigError(`${path}.format は必須です`, `${path}.format`, '例: `format: sarif`');
  }
  return {
    format,
    ...(output !== undefined ? { output } : {}),
    ...(failOn !== undefined ? { failOn } : {}),
  };
}

/** ルール定義の配列を正規化する。 */
export function normalizeRuleList<T>(
  value: unknown,
  path: string,
  normalize: (item: unknown, itemPath: string, options: NormalizeOptions) => T,
  options: NormalizeOptions = {},
): T[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) {
    throw new ConfigError(`${path} は配列である必要があります（実際: ${describeValue(value)}）`, path);
  }
  return value.map((item, index) => normalize(item, `${path}[${index}]`, options));
}

// ---------------------------------------------------------------------------
// ドキュメント検証
// ---------------------------------------------------------------------------

/** 空のルール定義。 */
function emptyRules(): ValidatedRules {
  return { sources: [], sanitizers: [], sinks: [], propagators: [] };
}

/** `rules:` セクションを検証する。 */
function validateRules(value: unknown, options: NormalizeOptions): ValidatedRules {
  const record = expectRecord(value, 'rules');
  warnUnknownKeys(record, ['sources', 'sanitizers', 'sinks', 'propagators', 'ignorePaths'], 'rules', options.onWarning);
  const ignorePaths = record['ignorePaths'] === undefined ? undefined : expectStringArray(record['ignorePaths'], 'rules.ignorePaths', true);
  return {
    sources: normalizeRuleList(record['sources'], 'rules.sources', normalizeSourceSpec, options),
    sanitizers: normalizeRuleList(record['sanitizers'], 'rules.sanitizers', normalizeSanitizerSpec, options),
    sinks: normalizeRuleList(record['sinks'], 'rules.sinks', normalizeSinkSpec, options),
    propagators: normalizeRuleList(record['propagators'], 'rules.propagators', normalizePropagator, options),
    ...(ignorePaths !== undefined ? { ignorePaths } : {}),
  };
}

/**
 * 解析済みの YAML ドキュメントを検証し、型付きの設定断片へ変換する。
 *
 * `null` / `undefined`（空ファイル）は空の設定として扱う。トップレベルの `ignorePaths` は
 * `rules.ignorePaths` の別名として受け付ける。
 */
export function validateDocument(doc: unknown, onWarning?: WarningSink): ValidatedDocument {
  if (doc === null || doc === undefined) return { rules: emptyRules() };
  const record = expectRecord(doc, 'config');
  warnUnknownKeys(record, ['version', 'schemaVersion', 'rules', 'analysis', 'output', 'ignorePaths'], '', onWarning);
  const options: NormalizeOptions = onWarning === undefined ? {} : { onWarning };

  let schemaVersion: 1 | undefined;
  const versionKey = record['version'] !== undefined ? 'version' : record['schemaVersion'] !== undefined ? 'schemaVersion' : undefined;
  if (versionKey !== undefined) {
    const rawVersion = record[versionKey];
    if (rawVersion !== 1) {
      throw new ConfigError(
        `${versionKey} は 1 のみ対応しています（実際: ${describeValue(rawVersion)}）`,
        versionKey,
        '古い設定ファイルは schemaVersion を確認してください',
      );
    }
    schemaVersion = 1;
  }

  let rules = record['rules'] === undefined ? emptyRules() : validateRules(record['rules'], options);
  if (record['ignorePaths'] !== undefined) {
    rules = { ...rules, ignorePaths: expectStringArray(record['ignorePaths'], 'ignorePaths', true) };
  }

  const analysis = record['analysis'] === undefined ? undefined : normalizeAnalysisConfig(record['analysis'], 'analysis', options);
  const output = record['output'] === undefined ? undefined : normalizeOutputConfig(record['output'], 'output', options);

  return {
    rules,
    ...(schemaVersion !== undefined ? { schemaVersion } : {}),
    ...(analysis !== undefined ? { analysis } : {}),
    ...(output !== undefined ? { output } : {}),
  };
}
