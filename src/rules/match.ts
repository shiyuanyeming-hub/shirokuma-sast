/**
 * パターン照合器 — メンバ式の解決とパターン一致判定。
 *
 * このモジュールはルール定義（`SourceSpec` / `SanitizerSpec` / `SinkSpec` / `PatternSpec`）を
 * 「解決済みの式」に対して照合する純関数だけを提供する。副作用は持たず、同じ入力に対して
 * 常に同じ結果を返す（解析結果の決定性を保証するため）。
 *
 * ## メンバ式の照合規則
 *
 * - `member: 'db.query'` は **接頭辞一致**: `db.query` と `db.query.id` の両方に一致する。
 * - `member: '.innerHTML'` のように先頭が `.` の場合は **接尾辞一致**:
 *   `el.innerHTML` や `document.body.innerHTML` に一致する。レシーバ名が構文上不定な
 *   プロパティシンク（DOM API など）を表現するための拡張。
 * - セグメント `*` は動的プロパティアクセス（`req[key]`）を表し、任意の 1 セグメントに一致する。
 *   `allowDynamic: true` を指定したパターンは、逆に `*` を含む式にも一致できる。
 * - `call` は呼び出し式の **単純名**（裸の識別子呼び出し、またはメンバ式の最終セグメント）に
 *   一致する。`User.find(...)` のようなレシーバ不定のメソッド呼び出しを拾うためであり、
 *   レシーバまで確定させたい場合は `member` を指定する。
 *   ただし `call` の一致は呼び出し式（`isCall === true`）に限られる。
 * - `identifier` は裸の識別子にのみ一致する。単一セグメントの式は `identifier` と `member` の
 *   両方を持つため、`req` のような引数名はどちらの指定でも拾える。
 */

import type { ResolvedExpression } from './annotate-contract.js';

/** `annotate-contract.ts` で定義された式表現型の再輸出（`match.ts` を単体で使う場合の入口）。 */
export type { ResolvedExpression };

/** メンバ式の解決結果を表す内部表現。`member` を構成するセグメントの配列。 */
type Segments = readonly string[];

/** 具体的な規則ほど大きくなる比較用スコア。辞書順で比較する。 */
export type Specificity = readonly [number, number, number, number];

/** 識別子の先頭に置ける文字。 */
const IDENTIFIER_START = /[A-Za-z_$]/;

/** 識別子の 2 文字目以降に置ける文字。 */
const IDENTIFIER_PART = /[A-Za-z0-9_$]/;

/** 単純識別子（ドットを含まない名前）かどうか。 */
const SIMPLE_IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/** 数値リテラル。 */
const NUMBER_LITERAL = /^[+-]?(?:\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\.\d+)$/;

/** シングルクォート文字列リテラル（1 行に収まるもの）。 */
const SINGLE_QUOTED = /^'(?:[^'\\\n]|\\.)*'$/;

/** ダブルクォート文字列リテラル（1 行に収まるもの）。 */
const DOUBLE_QUOTED = /^"(?:[^"\\\n]|\\.)*"$/;

/** 正規表現リテラルの開始とみなせる直前の文字。 */
const REGEX_ALLOWED_BEFORE = new Set(['', '(', '[', '{', ',', ';', ':', '=', '!', '&', '|', '?', '+', '-', '*', '%', '~', '^', '<', '>']);

/** 先頭から取り除くキーワード（ラベルに混ざる場合がある）。 */
const LEADING_KEYWORDS = ['await ', 'void ', 'yield '];

// ---------------------------------------------------------------------------
// 文字列スキャナ（文字列・テンプレート・コメントを区別する）
// ---------------------------------------------------------------------------

/**
 * ソーステキストの各位置が「コード」かどうかを示すマスクを作る。
 *
 * 文字列リテラル・テンプレートリテラルの本文・コメント・正規表現リテラルは `false` になり、
 * テンプレートリテラルの `${ ... }` の内部は `true` になる。
 * 括弧やカンマを「トップレベル」で探すための前処理であり、字句解析器を持ち込まずに
 * 実用的な精度を得ることを目的とする。
 */
function codeMask(text: string): boolean[] {
  const length = text.length;
  const mask: boolean[] = new Array<boolean>(length).fill(false);

  const scanQuoted = (start: number, quote: string): number => {
    let i = start + 1;
    while (i < length) {
      const ch = text.charAt(i);
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === quote) return i + 1;
      if (ch === '\n') return i;
      i += 1;
    }
    return length;
  };

  const scanRegexLiteral = (start: number): number => {
    let i = start + 1;
    let inClass = false;
    while (i < length) {
      const ch = text.charAt(i);
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === '\n') return i;
      if (ch === '[') inClass = true;
      else if (ch === ']') inClass = false;
      else if (ch === '/' && !inClass) return i + 1;
      i += 1;
    }
    return length;
  };

  const scanTemplate = (start: number): number => {
    let i = start + 1;
    while (i < length) {
      const ch = text.charAt(i);
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === '`') return i + 1;
      if (ch === '$' && text.charAt(i + 1) === '{') {
        i = scanCode(i + 2, true);
        continue;
      }
      i += 1;
    }
    return length;
  };

  const scanCode = (start: number, stopAtBrace: boolean): number => {
    let i = start;
    let depth = 0;
    let previous = '';
    while (i < length) {
      const ch = text.charAt(i);
      if (ch === '/' && text.charAt(i + 1) === '/') {
        i += 2;
        while (i < length && text.charAt(i) !== '\n') i += 1;
        continue;
      }
      if (ch === '/' && text.charAt(i + 1) === '*') {
        i += 2;
        while (i < length && !(text.charAt(i) === '*' && text.charAt(i + 1) === '/')) i += 1;
        i += 2;
        continue;
      }
      if (ch === '/' && REGEX_ALLOWED_BEFORE.has(previous)) {
        i = scanRegexLiteral(i);
        previous = '/';
        continue;
      }
      if (ch === "'" || ch === '"') {
        i = scanQuoted(i, ch);
        previous = ch;
        continue;
      }
      if (ch === '`') {
        i = scanTemplate(i);
        previous = '`';
        continue;
      }
      if (ch === '{') {
        depth += 1;
        mask[i] = true;
        i += 1;
        previous = ch;
        continue;
      }
      if (ch === '}') {
        // テンプレート式の終端。呼び出し側がテンプレート本文へ戻る。
        if (depth === 0 && stopAtBrace) return i + 1;
        if (depth > 0) depth -= 1;
        mask[i] = true;
        i += 1;
        previous = ch;
        continue;
      }
      mask[i] = true;
      if (ch.trim() !== '') previous = ch;
      i += 1;
    }
    return length;
  };

  scanCode(0, false);
  return mask;
}

/** トップレベル（文字列・コメント・括弧の外）にある最初の `(` の位置。無ければ -1。 */
function findTopLevelOpenParen(text: string): number {
  const mask = codeMask(text);
  let depth = 0;
  for (let i = 0; i < text.length; i += 1) {
    if (mask[i] !== true) continue;
    const ch = text.charAt(i);
    if (ch === '(') {
      if (depth === 0) return i;
      depth += 1;
      continue;
    }
    if (ch === '[' || ch === '{') {
      depth += 1;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
    }
  }
  return -1;
}

/** `open` 位置の開き括弧に対応する閉じ括弧の位置。見つからなければ -1。 */
function findMatchingBracket(text: string, open: number): number {
  const mask = codeMask(text);
  const opener = text.charAt(open);
  const closer = opener === '(' ? ')' : opener === '[' ? ']' : '}';
  let depth = 0;
  for (let i = open; i < text.length; i += 1) {
    if (mask[i] !== true) continue;
    const ch = text.charAt(i);
    if (ch === opener) {
      depth += 1;
      continue;
    }
    if (ch === closer) {
      depth -= 1;
      if (depth === 0) return i;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
    }
  }
  return -1;
}

/** 引数リストをトップレベルのカンマで分割する。 */
function splitTopLevelArgs(inner: string): string[] {
  const trimmed = inner.trim();
  if (trimmed === '') return [];
  const mask = codeMask(trimmed);
  const args: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < trimmed.length; i += 1) {
    if (mask[i] !== true) continue;
    const ch = trimmed.charAt(i);
    if (ch === '(' || ch === '[' || ch === '{') depth += 1;
    else if (ch === ')' || ch === ']' || ch === '}') depth -= 1;
    else if (ch === ',' && depth === 0) {
      args.push(trimmed.slice(start, i).trim());
      start = i + 1;
    }
  }
  args.push(trimmed.slice(start).trim());
  return args.filter((arg) => arg !== '');
}

// ---------------------------------------------------------------------------
// 式テキストの正規化とメンバ式の解決
// ---------------------------------------------------------------------------

/** ラベルに紛れ込むキーワード・セミコロン・型注釈を取り除く。 */
function stripExpressionNoise(text: string): string {
  let value = text.trim();
  while (value.endsWith(';')) value = value.slice(0, -1).trimEnd();
  let changed = true;
  while (changed) {
    changed = false;
    for (const keyword of LEADING_KEYWORDS) {
      if (value.startsWith(keyword)) {
        value = value.slice(keyword.length).trimStart();
        changed = true;
      }
    }
  }
  value = value.replace(/\s+(?:as|satisfies)\s+(?:const|[A-Za-z_$][\w$.<>,[\]|]*)\s*$/, '').trimEnd();
  return value;
}

/** メンバ式をセグメントへ分解する。解決できなければ undefined。 */
function splitSegments(chain: string): Segments {
  return chain.split('.').filter((segment) => segment !== '');
}

/** 文字列リテラルの本文を取り出す（単純なエスケープのみ解釈する）。 */
function unquote(text: string): string | undefined {
  const value = text.trim();
  if (SINGLE_QUOTED.test(value)) {
    return value.slice(1, -1).replace(/''/g, "'").replace(/\\(.)/g, '$1');
  }
  if (DOUBLE_QUOTED.test(value)) {
    return value.slice(1, -1).replace(/\\(.)/g, '$1');
  }
  return undefined;
}

/** ブラケットアクセス `a[...]` の中身をセグメントへ変換する。 */
function bracketSegment(inner: string): string {
  const literal = unquote(inner);
  if (literal !== undefined) return literal;
  return '*';
}

/** `require('name')` の形ならモジュール名を返す。 */
function moduleNameOfRequire(text: string, start: number): { readonly name: string; readonly end: number } | undefined {
  let i = start;
  const skipWs = (): void => {
    while (i < text.length && text.charAt(i).trim() === '') i += 1;
  };
  skipWs();
  if (text.charAt(i) !== '(') return undefined;
  const close = findMatchingBracket(text, i);
  if (close === -1) return undefined;
  const name = unquote(text.slice(i + 1, close));
  if (name === undefined) return undefined;
  return { name, end: close + 1 };
}

/**
 * プロパティアクセス連鎖を `a.b.c` 形式へ正規化する。
 *
 * 対応する構文:
 * - `req.query.id` / `req?.query?.id` / `req!.query`
 * - `require('child_process').exec`（分割 require をモジュール名へ解決）
 * - `obj['literal']`（文字列リテラル添字はセグメント化）
 * - `obj[dynamic]`（動的添字は `*` セグメント）
 * - `(req.query).id`（丸括弧によるグルーピング）
 *
 * 解決できない場合（演算子・関数呼び出しの結果に対する動的アクセスなど）は `undefined` を返す。
 * `unknown` を受け取るのは、IR のノード・TypeScript の AST ノード・生テキストの
 * いずれを渡されても扱えるようにするためである（`getText()` を持つオブジェクトは AST とみなす）。
 */
export function resolveMemberChain(expression: unknown): string | undefined {
  const text = expressionToText(expression);
  if (text === undefined) return undefined;
  const source = stripExpressionNoise(text);
  if (source === '') return undefined;
  const mask = codeMask(source);

  const segments: string[] = [];
  let i = 0;

  const skipWs = (): void => {
    while (i < source.length && source.charAt(i).trim() === '') i += 1;
  };

  const readIdentifier = (): string | undefined => {
    if (mask[i] !== true || !IDENTIFIER_START.test(source.charAt(i))) return undefined;
    const start = i;
    while (i < source.length && mask[i] === true && IDENTIFIER_PART.test(source.charAt(i))) i += 1;
    return source.slice(start, i);
  };

  const readProperty = (): string | undefined => {
    skipWs();
    const name = readIdentifier();
    if (name === undefined) return undefined;
    return name;
  };

  skipWs();
  if (source.charAt(i) === '(') {
    const close = findMatchingBracket(source, i);
    if (close === -1) return undefined;
    const inner = resolveMemberChain(source.slice(i + 1, close));
    if (inner === undefined) return undefined;
    segments.push(inner);
    i = close + 1;
  } else {
    const name = readIdentifier();
    if (name === undefined) return undefined;
    if (name === 'require') {
      const resolved = moduleNameOfRequire(source, i);
      if (resolved === undefined) return undefined;
      segments.push(resolved.name);
      i = resolved.end;
    } else {
      segments.push(name);
    }
  }

  for (;;) {
    skipWs();
    if (i >= source.length) break;
    const ch = source.charAt(i);
    if (ch === '!' && source.charAt(i + 1) !== '=') {
      i += 1;
      continue;
    }
    if (ch === '?' && source.charAt(i + 1) === '.') {
      i += 2;
      const property = readProperty();
      if (property === undefined) return undefined;
      segments.push(property);
      continue;
    }
    if (ch === '.') {
      i += 1;
      const property = readProperty();
      if (property === undefined) return undefined;
      segments.push(property);
      continue;
    }
    if (ch === '[') {
      const close = findMatchingBracket(source, i);
      if (close === -1) return undefined;
      segments.push(bracketSegment(source.slice(i + 1, close)));
      i = close + 1;
      continue;
    }
    return undefined;
  }

  if (segments.length === 0) return undefined;
  return segments.join('.');
}

/** `resolveMemberChain` が受け取れる値をテキストへ変換する。 */
function expressionToText(expression: unknown): string | undefined {
  if (typeof expression === 'string') return expression;
  if (typeof expression !== 'object' || expression === null) return undefined;
  // TypeScript の AST ノードはプロトタイプ上の getText() を持つため、スプレッドではなく参照で読む。
  const record = expression as { getText?: unknown; text?: unknown; label?: unknown; name?: unknown };
  const getText = record.getText;
  if (typeof getText === 'function') {
    try {
      const text: unknown = (getText as () => unknown).call(expression);
      if (typeof text === 'string') return text;
    } catch {
      return undefined;
    }
  }
  const textValue = record.text;
  if (typeof textValue === 'string' && textValue.trim() !== '') return textValue;
  const labelValue = record.label;
  if (typeof labelValue === 'string' && labelValue.trim() !== '') return labelValue;
  const nameValue = record.name;
  if (typeof nameValue === 'string' && nameValue.trim() !== '') return nameValue;
  return undefined;
}

/** メンバ式の最終セグメント。 */
function lastSegmentOf(chain: string): string {
  const segments = splitSegments(chain);
  const last = segments[segments.length - 1];
  return last ?? chain;
}

/** 呼び出し式の解析結果。 */
interface ParsedCall {
  readonly callee: string;
  readonly args: readonly string[];
}

/**
 * `callee(args)` 形式を解析する。
 *
 * 連鎖呼び出し（`db.query(sql).then(cb)`）は **最初の呼び出し** を代表として解決する。
 * ラベルが 80 文字で切り詰められ閉じ括弧が失われている場合（IR の `text` は末尾が `…`）でも、
 * 開き括弧以降を引数として復元する（長い SQL 文でも第 1 引数のリテラル判定を保つため）。
 * それ以外の形（演算子・関数呼び出しの結果を再度呼ぶ等）は undefined を返す。
 */
function parseCallText(text: string): ParsedCall | undefined {
  const source = stripExpressionNoise(text);
  if (source === '') return undefined;
  const open = findTopLevelOpenParen(source);
  if (open <= 0) return undefined;
  const close = findMatchingBracket(source, open);
  const rawCallee = source.slice(0, open).trim();
  if (rawCallee === '') return undefined;
  let callee = rawCallee;
  if (callee.startsWith('new ')) callee = callee.slice(4).trim();
  while (callee.endsWith('!')) callee = callee.slice(0, -1).trimEnd();
  if (callee === '') return undefined;
  if (close === -1) {
    return { callee, args: splitTopLevelArgs(source.slice(open + 1).replace(/…\s*$/, '')) };
  }
  // 切り詰めの目印（`…`）だけが続く場合は、呼び出し自体は完結しているとみなす。
  const rest = source.slice(close + 1).replace(/…\s*$/, '').trim();
  const trailing = rest === '' || rest === ';' || /^(\??\.[A-Za-z_$][A-Za-z0-9_$]*)+$/.test(rest) || rest.startsWith('.') || rest.startsWith('?.');
  if (!trailing) return undefined;
  return { callee, args: splitTopLevelArgs(source.slice(open + 1, close)) };
}

/** `parseExpression` のオプション。 */
export interface ParseExpressionOptions {
  /** ノード種別が `call` のとき true（テキストに括弧が無くても呼び出しとして扱う）。 */
  readonly isCall?: boolean;
  /** 第一候補で解決できなかったときに試すテキスト（ラベルなど）。 */
  readonly fallback?: string;
}

/**
 * ソーステキスト（または IR ノードのラベル）を照合可能な式へ変換する。
 *
 * 第一候補で何も解決できなかった場合のみ `fallback` を試す。戻り値は常に値を持ち、
 * 一致する規則が無い場合は `member` も `identifier` も未設定になる
 * （`isEmptyExpression` で判定できる）。
 */
export function parseExpression(text: string, options: ParseExpressionOptions = {}): ResolvedExpression {
  const isCallHint = options.isCall === true;
  const candidates = options.fallback !== undefined && options.fallback !== text ? [text, options.fallback] : [text];
  for (const candidate of candidates) {
    const expression = parseSingleCandidate(candidate, isCallHint);
    if (!isEmptyExpression(expression)) return expression;
  }
  return { isCall: isCallHint, argTexts: [], firstArgIsLiteral: false };
}

/** 単一のテキストを式へ変換する。 */
function parseSingleCandidate(text: string, isCallHint: boolean): ResolvedExpression {
  const trimmed = stripExpressionNoise(text);
  if (trimmed === '') return { isCall: isCallHint, argTexts: [], firstArgIsLiteral: false };

  const call = parseCallText(trimmed);
  if (call !== undefined) {
    const member = resolveMemberChain(call.callee);
    const firstArg = call.args.length > 0 ? call.args[0] : undefined;
    const base = {
      isCall: true,
      argTexts: call.args,
      firstArgIsLiteral: firstArg !== undefined && isLiteralText(firstArg),
    };
    if (member !== undefined) {
      const segments = splitSegments(member);
      return {
        ...base,
        member,
        last: lastSegmentOf(member),
        ...(segments.length === 1 && SIMPLE_IDENTIFIER.test(member) ? { identifier: member } : {}),
      };
    }
    if (SIMPLE_IDENTIFIER.test(call.callee)) {
      return { ...base, identifier: call.callee };
    }
    return base;
  }

  const member = resolveMemberChain(trimmed);
  if (member !== undefined) {
    const segments = splitSegments(member);
    return {
      ...(segments.length === 1 && SIMPLE_IDENTIFIER.test(member) ? { identifier: member } : {}),
      member,
      last: lastSegmentOf(member),
      isCall: isCallHint,
      argTexts: [],
      firstArgIsLiteral: false,
    };
  }
  if (SIMPLE_IDENTIFIER.test(trimmed)) {
    return { identifier: trimmed, isCall: isCallHint, argTexts: [], firstArgIsLiteral: false };
  }
  return { isCall: isCallHint, argTexts: [], firstArgIsLiteral: false };
}

/** メンバ式も識別子も解決できなかった（＝どのパターンにも一致しない）かどうか。 */
export function isEmptyExpression(expression: ResolvedExpression): boolean {
  return expression.member === undefined && expression.identifier === undefined;
}

// ---------------------------------------------------------------------------
// リテラル判定
// ---------------------------------------------------------------------------

/**
 * 第 1 引数が「文字列リテラル」または「補間のないテンプレートリテラル」かどうか。
 *
 * `ResolvedExpression.firstArgIsLiteral` の定義そのものであり、
 * `validation: 'static-sql'` の判定に使う。
 */
export function isLiteralText(text: string): boolean {
  let value = text.trim();
  let guard = 0;
  while (value.startsWith('(') && value.endsWith(')') && guard < 8) {
    const close = findMatchingBracket(value, 0);
    if (close !== value.length - 1) break;
    value = value.slice(1, -1).trim();
    guard += 1;
  }
  if (SINGLE_QUOTED.test(value) || DOUBLE_QUOTED.test(value)) return true;
  if (value.startsWith('`') && value.endsWith('`') && value.length >= 2) {
    let i = 1;
    while (i < value.length - 1) {
      const ch = value.charAt(i);
      if (ch === '\\') {
        i += 2;
        continue;
      }
      if (ch === '$' && value.charAt(i + 1) === '{') return false;
      i += 1;
    }
    return true;
  }
  return false;
}

/**
 * `validation: 'constant-argument'` 用の定数判定。
 *
 * 文字列リテラル・補間なしテンプレートに加え、数値・真偽値・`null` / `undefined` も定数として扱う。
 * 変数・プロパティアクセス・関数呼び出しは定数ではない。
 */
export function isConstantArgumentText(text: string): boolean {
  if (isLiteralText(text)) return true;
  const value = text.trim();
  if (NUMBER_LITERAL.test(value)) return true;
  return value === 'true' || value === 'false' || value === 'null' || value === 'undefined';
}

// ---------------------------------------------------------------------------
// パターン一致
// ---------------------------------------------------------------------------

/** パターンが指定している照合条件。 */
export interface MatchablePattern {
  readonly member?: string;
  readonly identifier?: string;
  readonly call?: string;
  readonly allowDynamic?: boolean;
}

/** 単一セグメントの一致。パターン側の `*` は常にワイルドカード。 */
function segmentMatches(patternSegment: string, expressionSegment: string, allowDynamic: boolean): boolean {
  if (patternSegment === '*') return true;
  // 式中の `*` は動的プロパティアクセス。`allowDynamic` のときだけ未知セグメントとして一致させる。
  if (expressionSegment === '*') return allowDynamic;
  return patternSegment === expressionSegment;
}

/** 接尾辞パターン（先頭 `.`）の一致。 */
function matchesSuffix(patternSegments: Segments, expressionSegments: Segments, allowDynamic: boolean): boolean {
  if (patternSegments.length > expressionSegments.length) return false;
  const offset = expressionSegments.length - patternSegments.length;
  for (let i = 0; i < patternSegments.length; i += 1) {
    const patternSegment = patternSegments[i];
    const expressionSegment = expressionSegments[offset + i];
    if (patternSegment === undefined || expressionSegment === undefined) return false;
    if (!segmentMatches(patternSegment, expressionSegment, allowDynamic)) return false;
  }
  return true;
}

/** 接頭辞パターンの一致。 */
function matchesPrefix(patternSegments: Segments, expressionSegments: Segments, allowDynamic: boolean): boolean {
  if (patternSegments.length > expressionSegments.length) return false;
  for (let i = 0; i < patternSegments.length; i += 1) {
    const patternSegment = patternSegments[i];
    const expressionSegment = expressionSegments[i];
    if (patternSegment === undefined || expressionSegment === undefined) return false;
    if (!segmentMatches(patternSegment, expressionSegment, allowDynamic)) return false;
  }
  return true;
}

/**
 * パターン定義が式に一致するかどうかを判定する。
 *
 * `member` / `identifier` / `call` のうち指定された条件は **すべて** 満たす必要がある（AND）。
 * どれも指定されていないパターンは何にも一致しない（設定ミスを黙って許さないため）。
 */
export function matchesPattern(pattern: MatchablePattern, expr: ResolvedExpression): boolean {
  const member = pattern.member !== undefined && pattern.member !== '' ? pattern.member : undefined;
  const identifier = pattern.identifier !== undefined && pattern.identifier !== '' ? pattern.identifier : undefined;
  const call = pattern.call !== undefined && pattern.call !== '' ? pattern.call : undefined;
  if (member === undefined && identifier === undefined && call === undefined) return false;

  const allowDynamic = pattern.allowDynamic === true;

  if (member !== undefined) {
    if (expr.member === undefined) return false;
    const expressionSegments = splitSegments(expr.member);
    if (member.startsWith('.')) {
      const suffixSegments = splitSegments(member.slice(1));
      if (suffixSegments.length === 0) return false;
      if (!matchesSuffix(suffixSegments, expressionSegments, allowDynamic)) return false;
    } else {
      const patternSegments = splitSegments(member);
      if (patternSegments.length === 0) return false;
      if (!matchesPrefix(patternSegments, expressionSegments, allowDynamic)) return false;
    }
  }

  if (identifier !== undefined) {
    if (expr.identifier !== identifier) return false;
  }

  if (call !== undefined) {
    if (!expr.isCall) return false;
    const simpleName = expr.member !== undefined ? expr.last : expr.identifier;
    if (simpleName === undefined || simpleName !== call) return false;
  }

  return true;
}

/**
 * 一致の具体度を表すスコア。`member` のセグメント数 → `member` の文字数 →
 * `identifier` の文字数 → `call` の文字数の順に比較する（辞書順・降順が優先）。
 */
export function patternSpecificity(pattern: MatchablePattern): Specificity {
  const member = pattern.member ?? '';
  const rawSegments = member.startsWith('.') ? member.slice(1) : member;
  return [splitSegments(rawSegments).length, member.length, (pattern.identifier ?? '').length, (pattern.call ?? '').length];
}

/**
 * スコアの辞書順比較。`a` の方が具体的なら正、`b` の方が具体的なら負、等しければ 0。
 * `matchMostSpecific` と同じ基準を呼び出し側で使いたい場合に公開している。
 */
export function compareSpecificity(a: Specificity, b: Specificity): number {
  for (let i = 0; i < a.length; i += 1) {
    const left = a[i] ?? 0;
    const right = b[i] ?? 0;
    if (left !== right) return left - right;
  }
  return 0;
}

/**
 * 複数のパターンのうち、最も具体的に一致したものを返す。
 *
 * 具体度が同じ場合は **先に宣言されたもの** を優先する（規則の並び順が意味を持つ）。
 * 一致するパターンが無ければ undefined。
 */
export function matchMostSpecific<T extends MatchablePattern>(patterns: readonly T[], expr: ResolvedExpression): T | undefined {
  let best: T | undefined;
  let bestScore: Specificity | undefined;
  for (const pattern of patterns) {
    if (!matchesPattern(pattern, expr)) continue;
    const score = patternSpecificity(pattern);
    if (best === undefined || bestScore === undefined || compareSpecificity(score, bestScore) > 0) {
      best = pattern;
      bestScore = score;
    }
  }
  return best;
}
