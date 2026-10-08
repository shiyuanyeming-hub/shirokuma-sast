/**
 * TypeScript AST を扱う低レベル補助関数。
 *
 * IR 構築から使うため、副作用を持たず、同じ入力に対して常に同じ結果を返す。
 * ここでは「ソースコード上の何を指しているか」だけを扱い、
 * ルール（ソース／サニタイザ／シンク）の判定は行わない。
 */
import ts from 'typescript';

/** 分割代入を含む束縛パターンを `変数名 → その値を表す式` の組へ展開する。 */
export interface BindingLeaf {
  /** 束縛される変数名。 */
  readonly name: string;
  /** 変数へ到達するために辿るプロパティ名（`const {a: {b}} = x` なら `['a', 'b']`）。 */
  readonly path: readonly string[];
  /** 配列分割代入で使う添字（`const [a] = x` なら 0）。プロパティ名でない場合に使う。 */
  readonly index?: number;
  /** この束縛の初期値式（既定値がある場合のみ）。 */
  readonly initializer?: ts.Expression;
  /** 束縛要素のノード（位置情報の取得に使う）。 */
  readonly node: ts.Node;
}

/** 束縛名（Identifier）を取り出す。`this` など対象外なら undefined。 */
export function bindingName(node: ts.BindingName): string | undefined {
  if (ts.isIdentifier(node)) {
    return node.text;
  }
  return undefined;
}

/** 変数宣言の宣言名を文字列で返す。分割代入なら undefined（`bindingLeaves` を使う）。 */
export function declaredName(name: ts.BindingName): string | undefined {
  return bindingName(name);
}

/**
 * 束縛パターンを葉（実際に束縛される変数）の一覧へ展開する。
 * ネストした分割代入・配列分割代入・残余要素・既定値に対応する。
 */
export function bindingLeaves(name: ts.BindingName, prefix: readonly string[] = []): readonly BindingLeaf[] {
  const leaves: BindingLeaf[] = [];

  if (ts.isIdentifier(name)) {
    leaves.push({ name: name.text, path: prefix, node: name });
    return leaves;
  }

  if (ts.isObjectBindingPattern(name)) {
    for (const element of name.elements) {
      const key = propertyKeyText(element.propertyName) ?? bindingName(element.name);
      const nextPath = key === undefined ? prefix : [...prefix, key];
      const nested = bindingLeaves(element.name, nextPath);
      for (const leaf of nested) {
        leaves.push(element.initializer === undefined ? leaf : { ...leaf, initializer: element.initializer });
      }
    }
    return leaves;
  }

  if (ts.isArrayBindingPattern(name)) {
    let index = 0;
    for (const element of name.elements) {
      if (ts.isOmittedExpression(element)) {
        index += 1;
        continue;
      }
      const nested = bindingLeaves(element.name, prefix);
      for (const leaf of nested) {
        const withIndex: BindingLeaf = { ...leaf, index };
        leaves.push(element.initializer === undefined ? withIndex : { ...withIndex, initializer: element.initializer });
      }
      index += 1;
    }
    return leaves;
  }

  return leaves;
}

/** プロパティ名（`{ a: b }` の `a`）を文字列で返す。 */
export function propertyKeyText(name: ts.PropertyName | undefined): string | undefined {
  if (name === undefined) {
    return undefined;
  }
  if (ts.isIdentifier(name) || ts.isPrivateIdentifier(name)) {
    return name.text;
  }
  if (ts.isStringLiteral(name) || ts.isNumericLiteral(name)) {
    return name.text;
  }
  return undefined;
}

/**
 * 式からメンバ式（`a.b.c`）を組み立てる。
 *
 * - `require('express')` は `express` として解決する（分割 require 対応）。
 * - 動的プロパティ `a[b]` は `a` の部分だけで解決を打ち切る（`undefined` を返さない）。
 * - `this` は `this` として残す（メソッド解決側でクラス文脈と突き合わせる）。
 */
export function memberChainOf(expression: ts.Expression): string | undefined {
  if (ts.isIdentifier(expression)) {
    return expression.text;
  }
  if (expression.kind === ts.SyntaxKind.ThisKeyword) {
    return 'this';
  }
  if (ts.isParenthesizedExpression(expression)) {
    return memberChainOf(expression.expression);
  }
  if (ts.isNonNullExpression(expression)) {
    return memberChainOf(expression.expression);
  }
  if (ts.isPropertyAccessExpression(expression)) {
    const left = memberChainOf(expression.expression);
    if (left === undefined) {
      return undefined;
    }
    return `${left}.${expression.name.text}`;
  }
  if (ts.isElementAccessExpression(expression)) {
    const left = memberChainOf(expression.expression);
    const key = literalKeyOf(expression.argumentExpression);
    if (left === undefined) {
      return undefined;
    }
    return key === undefined ? left : `${left}.${key}`;
  }
  if (ts.isCallExpression(expression)) {
    // `require('child_process')` ↔ `child_process`
    const callee = memberChainOf(expression.expression);
    if (callee === 'require' && expression.arguments.length === 1) {
      const first = expression.arguments[0];
      if (first !== undefined && ts.isStringLiteralLike(first)) {
        const withoutScope = first.text.startsWith('@') ? first.text.split('/').slice(0, 2).join('/') : first.text.split('/')[0];
        return withoutScope;
      }
    }
    return undefined;
  }
  return undefined;
}

/** 要素アクセスの鍵がリテラルならその文字列を返す。 */
export function literalKeyOf(expression: ts.Expression | undefined): string | undefined {
  if (expression === undefined) {
    return undefined;
  }
  if (ts.isStringLiteralLike(expression) || ts.isNumericLiteral(expression)) {
    return expression.text;
  }
  return undefined;
}

/** メンバ式の最後のセグメント（`a.b.c` → `c`）。 */
export function lastSegment(chain: string | undefined): string | undefined {
  if (chain === undefined) {
    return undefined;
  }
  const parts = chain.split('.');
  return parts[parts.length - 1];
}

/** 文字列リテラル（テンプレートの補間なしを含む）かどうか。 */
export function isStaticLiteral(expression: ts.Expression | undefined): boolean {
  if (expression === undefined) {
    return false;
  }
  if (ts.isStringLiteralLike(expression) || ts.isNumericLiteral(expression)) {
    return true;
  }
  if (ts.isNoSubstitutionTemplateLiteral(expression)) {
    return true;
  }
  return false;
}

/** 補間を含むテンプレートリテラルかどうか。 */
export function isInterpolatedTemplate(expression: ts.Expression | undefined): boolean {
  if (expression === undefined) {
    return false;
  }
  if (!ts.isTemplateExpression(expression)) {
    return false;
  }
  return expression.templateSpans.length > 0;
}

/**
 * 「第 1 引数がリテラルか」を判定する。
 * サニタイザの `static-sql` 検証（プレースホルダ用法かどうか）で使う。
 */
export function isFirstArgumentLiteral(call: ts.CallExpression): boolean {
  const first = call.arguments[0];
  if (first === undefined) {
    return false;
  }
  if (ts.isNoSubstitutionTemplateLiteral(first)) {
    return true;
  }
  if (ts.isTemplateExpression(first)) {
    return false;
  }
  return ts.isStringLiteralLike(first) || ts.isNumericLiteral(first);
}

/** 関数風ノード（関数宣言・関数式・アロー関数・メソッド宣言）かどうか。 */
export function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclaration {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node) ||
    ts.isConstructorDeclaration(node)
  );
}

/** 関数風ノードの名前を返す。無名なら `undefined`。 */
export function functionLikeName(node: ts.FunctionLikeDeclaration): string | undefined {
  if (ts.isConstructorDeclaration(node)) {
    return 'constructor';
  }
  if (ts.isFunctionDeclaration(node) || ts.isFunctionExpression(node)) {
    return node.name?.text;
  }
  if (ts.isMethodDeclaration(node) || ts.isGetAccessorDeclaration(node) || ts.isSetAccessorDeclaration(node)) {
    return propertyKeyText(node.name);
  }
  return undefined;
}

/** クラス宣言・クラス式の名前を返す。 */
export function classNameOf(node: ts.ClassLikeDeclaration): string | undefined {
  return node.name?.text;
}

/** ソーステキストから位置情報（1-based）を作る。 */
export function rangeOfNode(node: ts.Node, source: ts.SourceFile): { start: { line: number; column: number }; end: { line: number; column: number } } {
  const start = source.getLineAndCharacterOfPosition(node.getStart(source));
  const end = source.getLineAndCharacterOfPosition(node.getEnd());
  return {
    start: { line: start.line + 1, column: start.character + 1 },
    end: { line: end.line + 1, column: end.character + 1 },
  };
}

/**
 * 式をレポート用のラベル文字列にする。
 *
 * `a.b` はメンバ式として解決する。解決できない動的アクセスは
 * 括弧つきの短い表記（`o[req.query.k]`）にして、どの値かを人が追えるようにする。
 */
export function labelExpression(expression: ts.Expression, source: ts.SourceFile): string {
  const chain = memberChainOf(expression);
  if (chain !== undefined) {
    return chain;
  }
  if (ts.isElementAccessExpression(expression)) {
    const base = memberChainOf(expression.expression) ?? expression.expression.getText(source);
    const key = expression.argumentExpression.getText(source);
    return `${base}[${key}]`;
  }
  return expression.getText(source);
}

/** 要素アクセスの鍵がリテラル（静的に解決できる）かどうか。 */
export function isStaticElementAccess(expression: ts.ElementAccessExpression): boolean {
  return literalKeyOf(expression.argumentExpression) !== undefined;
}

/**
 * プロパティ読み書きのラベル。
 *
 * 静的に解決できるアクセスは `a.b.c` の形にする。動的な要素アクセス
 * （`o[req.query.k]`）はメンバ式として解決できず基底名に潰れてしまうため、
 * 鍵が動的であることが分かる表記へ置き換える。これにより
 * 「基底」と「読み出し結果」が別のノードとして区別される。
 */
export function propertyLabel(expression: ts.Expression, source: ts.SourceFile): string {
  if (ts.isElementAccessExpression(expression) && !isStaticElementAccess(expression)) {
    const base = memberChainOf(expression.expression) ?? collapseForLabel(expression.expression, source);
    return `${base}[<dynamic>]`;
  }
  return memberChainOf(expression) ?? expression.getText(source);
}

/** 短いラベル用に式のテキストを 1 行へ畳む。 */
function collapseForLabel(expression: ts.Expression, source: ts.SourceFile): string {
  return expression.getText(source).replace(/\s+/g, ' ').slice(0, 40);
}

/** 配列の一意化（順序は保ったまま）。 */
export function unique<T>(values: readonly T[]): readonly T[] {
  return [...new Set(values)];
}
