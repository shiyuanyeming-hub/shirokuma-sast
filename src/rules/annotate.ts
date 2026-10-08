/**
 * ルール適用（アノテーション）— `IRGraph` と `ResolvedRuleSet` の突き合わせ。
 *
 * IR 構築は「どの式がソース／サニタイザ／シンクか」を知らない。このモジュールが
 * ノードのラベル・テキストを式として解決し、ルール定義と照合して確定情報を作る。
 *
 * ## 照合の要点
 * - `member` は接頭辞一致（`req.query` の規則は `req.query.id` にも一致）、
 *   先頭 `.` のパターンは接尾辞一致（`.innerHTML` は `el.innerHTML` に一致）。
 * - 同じノードに複数のソース／サニタイザが一致した場合は **最も具体的な 1 件** を採用する。
 * - シンクは同じ具体度で複数一致した場合のみ全件を残す（同じ式が複数の脆弱性クラスに
 *   該当することを許すため）。具体度が劣る規則は捨てる。
 * - `require('mod')` の別名（`const cp = require('child_process')`）を解決し、
 *   `cp.exec()` を `child_process.exec()` として照合する。
 * - サニタイザの `validation` は呼び出し引数まで見て判定し、無効なら `valid: false` と
 *   日本語の理由を付ける（＝汚染は残る）。
 *
 * 出力は常に `nodeId` → 規則 ID の順にソートされ、同じ入力に対して同一になる。
 */
import type {
  FlowNode,
  FunctionIR,
  IRGraph,
  ResolvedRuleSet,
  SanitizerOccurrence,
  SanitizerSpec,
  SinkOccurrence,
  SourceOccurrence,
  SourceSpec,
} from '../types.js';
import type { AnnotatedGraph, AnnotateResult, ResolvedExpression } from './annotate-contract.js';
import {
  compareSpecificity,
  isConstantArgumentText,
  isEmptyExpression,
  matchesPattern,
  matchMostSpecific,
  parseExpression,
  patternSpecificity,
} from './match.js';

/** `annotate-contract.ts` で定義された公開型の再輸出（`annotate.ts` を単体で使う場合の入口）。 */
export type { AnnotatedGraph, AnnotateResult };

/** 別名解決の最大ホップ数（`const a = b` の連鎖で循環しないための上限）。 */
const MAX_ALIAS_HOPS = 8;

/** ドキュメント上で固定されているタグ語彙。 */
const TAG_VOCABULARY: readonly string[] = ['code', 'command', 'header', 'html', 'nosql', 'path', 'sql', 'unknown', 'url'];

/** コード単位での文字列比較（ロケール非依存＝環境によらず決定的）。 */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/** メンバ式をセグメントへ分解する。 */
function toSegments(chain: string): string[] {
  return chain.split('.').filter((segment) => segment !== '');
}

// ---------------------------------------------------------------------------
// 式の解決
// ---------------------------------------------------------------------------

/** `require('mod')` の別名定義を 1 つのテキストから抽出する。 */
function collectAliasFromText(text: string, aliases: Map<string, string>): void {
  const source = text.trim().replace(/;$/, '').trim();
  const simple = /^(?:(?:const|let|var)\s+)?([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*require\s*\(\s*(['"])([^'"]+)\2\s*\)((?:\.[A-Za-z_$][A-Za-z0-9_$]*)*)$/.exec(source);
  if (simple !== null) {
    const [, name, , moduleName, tail] = simple;
    if (name !== undefined && moduleName !== undefined) {
      aliases.set(name, `${moduleName}${tail ?? ''}`.replace(/\.default$/, ''));
    }
    return;
  }
  const destructured = /^(?:(?:const|let|var)\s+)?\{([^}]*)\}\s*=\s*require\s*\(\s*(['"])([^'"]+)\2\s*\)$/.exec(source);
  if (destructured !== null) {
    const [, bindings, , moduleName] = destructured;
    if (bindings === undefined || moduleName === undefined) return;
    for (const raw of bindings.split(',')) {
      const binding = raw.trim();
      if (binding === '' || binding.startsWith('...')) continue;
      const [imported, local] = binding.split(':').map((part) => part.trim());
      if (imported === undefined || imported === '') continue;
      const target = local !== undefined && local !== '' ? local : imported;
      aliases.set(target, `${moduleName}.${imported}`);
    }
  }
}

/** グラフ中の `require` 別名を集める。 */
function collectRequireAliases(nodes: readonly FlowNode[]): ReadonlyMap<string, string> {
  const aliases = new Map<string, string>();
  for (const node of nodes) {
    if (node.text !== undefined) collectAliasFromText(node.text, aliases);
    collectAliasFromText(node.label, aliases);
  }
  return aliases;
}

/** 別名をメンバ式のルートへ適用する（`cp.exec` → `child_process.exec`）。 */
function applyAliases(expression: ResolvedExpression, aliases: ReadonlyMap<string, string>): ResolvedExpression {
  if (aliases.size === 0) return expression;
  const segments = expression.member !== undefined ? toSegments(expression.member) : [];
  const root = segments.length > 0 ? segments[0] : expression.identifier;
  if (root === undefined) return expression;
  const seen = new Set<string>([root]);
  let resolved = root;
  for (let hop = 0; hop < MAX_ALIAS_HOPS; hop += 1) {
    const next = aliases.get(resolved);
    if (next === undefined || next === '' || seen.has(next)) break;
    seen.add(next);
    resolved = next;
  }
  if (resolved === root) return expression;
  const member = [resolved, ...segments.slice(1)].join('.');
  const memberSegments = toSegments(member);
  return { ...expression, member, last: memberSegments[memberSegments.length - 1] ?? member };
}

/** ノード 1 件を照合可能な式へ変換する。 */
function expressionForNode(node: FlowNode, aliases: ReadonlyMap<string, string>): ResolvedExpression {
  const isCall = node.kind === 'call';
  const primary = node.text !== undefined && node.text.trim() !== '' ? node.text : node.label;
  const options = primary === node.label ? { isCall } : { isCall, fallback: node.label };
  let expression = parseExpression(primary, options);
  if (isEmptyExpression(expression) && primary !== node.label) {
    expression = parseExpression(node.label, { isCall });
  }
  return applyAliases(expression, aliases);
}

// ---------------------------------------------------------------------------
// 適用条件の判定
// ---------------------------------------------------------------------------

/** 関数の呼び名（名前・`Class.name`・関数 ID）を列挙する。 */
function functionNames(fn: FunctionIR): string[] {
  const names = new Set<string>([fn.name, fn.id]);
  if (fn.className !== undefined && fn.className !== '') {
    names.add(`${fn.className}.${fn.name}`);
    names.add(`${fn.className}::${fn.name}`);
  }
  const parts = fn.id.split('::');
  if (parts.length > 1) {
    names.add(parts.slice(1).join('::'));
    const last = parts[parts.length - 1];
    if (last !== undefined && last !== '') names.add(last);
  }
  return [...names];
}

/** ソースの `withinFunctions` を満たすか。 */
function withinAllowedFunctions(spec: SourceSpec, fn: FunctionIR | undefined): boolean {
  const allowed = spec.withinFunctions;
  if (allowed === undefined || allowed.length === 0) return true;
  if (fn === undefined) return false;
  const names = new Set(functionNames(fn));
  return allowed.some((name) => names.has(name));
}

/** サニタイザの `validation` 判定結果。 */
interface SanitizerValidation {
  readonly valid: boolean;
  readonly reason?: string;
}

/**
 * サニタイザが正しく使われているかを検証する。
 *
 * - `static-sql`: 第 1 引数が文字列リテラル／補間なしテンプレートのときだけ有効。
 *   変数を連結した SQL（`db.query(sqlVar)`）は **無効** であり、汚染は残る。
 * - `constant-argument`: 第 1 引数が定数のときだけ有効（許可リストの基準ディレクトリなど）。
 */
function validateSanitizerUsage(spec: SanitizerSpec, expr: ResolvedExpression): SanitizerValidation {
  const validation = spec.validation ?? 'none';
  if (validation === 'none') return { valid: true };
  if (!expr.isCall) {
    return { valid: false, reason: `呼び出し式ではないため ${validation} を検証できません（汚染は残ります）` };
  }
  const firstArg = expr.argTexts.length > 0 ? expr.argTexts[0] : undefined;
  if (firstArg === undefined) {
    return { valid: false, reason: '第 1 引数が無いため検証できません（汚染は残ります）' };
  }
  if (validation === 'static-sql') {
    if (expr.firstArgIsLiteral) return { valid: true };
    return { valid: false, reason: 'SQL 文が文字列リテラルではないため、プレースホルダ化されていません（汚染は残ります）' };
  }
  if (isConstantArgumentText(firstArg)) return { valid: true };
  return { valid: false, reason: '第 1 引数が定数ではないため、安全な呼び出しと確認できません（汚染は残ります）' };
}

/**
 * シンクの `taintedArgs` 既定値。
 *
 * 引数が特定できるときは全引数の位置を並べる。特定できないとき（ラベルに括弧が無い場合）は
 * 空配列を返す。解析エンジン側では空配列を「すべての引数」の意味で扱う規約になっている。
 */
function defaultTaintedArgs(expr: ResolvedExpression): number[] {
  if (expr.argTexts.length === 0) return [];
  return expr.argTexts.map((_arg, index) => index);
}

/** サニタイザが無害化できるタグ。空配列（＝すべて）は語彙へ展開する。 */
function sanitizerKinds(spec: SanitizerSpec, vocabulary: readonly string[]): string[] {
  return spec.kinds.length > 0 ? [...spec.kinds] : [...vocabulary];
}

/** ルールセットが扱うタグの語彙（ソースとシンクから集める）。 */
function collectVocabulary(rules: ResolvedRuleSet): readonly string[] {
  const kinds = new Set<string>();
  for (const source of rules.sources) for (const kind of source.kinds) kinds.add(kind);
  for (const sink of rules.sinks) for (const kind of sink.kinds) kinds.add(kind);
  if (kinds.size === 0) for (const kind of TAG_VOCABULARY) kinds.add(kind);
  return [...kinds].sort(compareStrings);
}

/** 一致したパターンのうち、最も具体的なものだけを残す（同点は全件）。 */
function mostSpecificAll<T extends { readonly member?: string; readonly identifier?: string; readonly call?: string }>(
  patterns: readonly T[],
  expr: ResolvedExpression,
): T[] {
  const matched = patterns.filter((pattern) => matchesPattern(pattern, expr));
  if (matched.length <= 1) return matched;
  const first = matched[0];
  if (first === undefined) return matched;
  let best = patternSpecificity(first);
  for (const pattern of matched) {
    const score = patternSpecificity(pattern);
    if (compareSpecificity(score, best) > 0) best = score;
  }
  return matched.filter((pattern) => compareSpecificity(patternSpecificity(pattern), best) === 0);
}

// ---------------------------------------------------------------------------
// 本体
// ---------------------------------------------------------------------------

/**
 * グラフ全体へルールを適用する。
 *
 * 戻り値の各配列は `nodeId` → 規則 ID の順にソート済みで、同じ入力に対して常に同じ順序になる。
 */
export function annotate(graph: IRGraph, rules: ResolvedRuleSet): AnnotateResult {
  const functions = new Map<string, FunctionIR>();
  for (const fn of graph.functions) functions.set(fn.id, fn);
  const aliases = collectRequireAliases(graph.nodes);
  const vocabulary = collectVocabulary(rules);
  const nodes = [...graph.nodes].sort((a, b) => compareStrings(a.id, b.id));

  const sources: SourceOccurrence[] = [];
  const sanitizers: SanitizerOccurrence[] = [];
  const sinks: SinkOccurrence[] = [];

  for (const node of nodes) {
    const expression = expressionForNode(node, aliases);
    if (isEmptyExpression(expression)) continue;
    const fn = functions.get(node.functionId);

    // --- ソース: 最も具体的な 1 件 ---
    const sourceCandidates = rules.sources.filter((spec) => withinAllowedFunctions(spec, fn));
    const source = matchMostSpecific(sourceCandidates, expression);
    if (source !== undefined) {
      sources.push({
        nodeId: node.id,
        sourceId: source.id,
        kinds: [...source.kinds],
        functionId: node.functionId,
        range: node.range,
        label: node.label,
      });
    }

    // --- サニタイザ: 最も具体的な 1 件（用法の検証付き） ---
    const sanitizer = matchMostSpecific(rules.sanitizers, expression);
    if (sanitizer !== undefined) {
      const validation = validateSanitizerUsage(sanitizer, expression);
      sanitizers.push({
        nodeId: node.id,
        sanitizerId: sanitizer.id,
        kinds: sanitizerKinds(sanitizer, vocabulary),
        valid: validation.valid,
        ...(validation.reason !== undefined ? { invalidReason: validation.reason } : {}),
        functionId: node.functionId,
        range: node.range,
      });
    }

    // --- シンク: 最も具体的な族をすべて（同一式が複数クラスに該当しうる） ---
    for (const sink of mostSpecificAll(rules.sinks, expression)) {
      const taintedArgs = sink.taintedArgs !== undefined ? [...sink.taintedArgs] : defaultTaintedArgs(expression);
      sinks.push({
        nodeId: node.id,
        sinkId: sink.id,
        kinds: [...sink.kinds],
        severity: sink.severity,
        message: sink.message,
        ...(sink.advice !== undefined ? { advice: sink.advice } : {}),
        ...(sink.cwe !== undefined ? { cwe: [...sink.cwe] } : {}),
        functionId: node.functionId,
        range: node.range,
        label: node.label,
        taintedArgs,
      });
    }
  }

  sources.sort((a, b) => compareStrings(a.nodeId, b.nodeId) || compareStrings(a.sourceId, b.sourceId));
  sanitizers.sort((a, b) => compareStrings(a.nodeId, b.nodeId) || compareStrings(a.sanitizerId, b.sanitizerId));
  sinks.sort((a, b) => compareStrings(a.nodeId, b.nodeId) || compareStrings(a.sinkId, b.sinkId));

  return { sources, sanitizers, sinks };
}

/** `annotate` の結果をグラフと束ねて返す（解析エンジン向けの便宜関数）。 */
export function annotateGraph(graph: IRGraph, rules: ResolvedRuleSet): AnnotatedGraph {
  const result = annotate(graph, rules);
  return { graph, sources: result.sources, sanitizers: result.sanitizers, sinks: result.sinks };
}
