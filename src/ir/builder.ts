/**
 * IR 構築の実装。
 *
 * TypeScript の AST を、解析エンジンが消費するデータフローグラフ（DFG）へ変換する。
 * ルール（ソース／サニタイザ／シンク）には一切依存しない。判定は後段の
 * `src/rules/annotate.ts` が行う。
 *
 * 構築は 2 段階で進む:
 *   1. 宣言の収集 — 関数・メソッド・仮引数・変数の値ノードを作り、
 *      前方参照（関数の巻き上げ・相互再帰）を解決できるようにする。
 *   2. 本体の走査 — 各式のノードと辺を作る。この段で得た
 *      「呼び出しの第 i 引数 → コールバックの第 i 仮引数」の対応は
 *      `SolverHints` として解析エンジンへ渡す。
 *
 * フロー感度について:
 *   同一関数内では「その位置より前に終わっている直近の宣言」を読む（フロー感度あり）。
 *   前に宣言が無い場合は最初の宣言へ結ぶ（前方参照）。関数をまたぐ流れは
 *   呼び出し辺とサマリで扱うため、ここでは関数単位の解析に留める。
 */
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import type {
  CallSite,
  Diagnostic,
  FlowEdge,
  FlowKind,
  FlowNode,
  FunctionIR,
  IRGraph,
  ParamIR,
  SourceFileInfo,
} from '../types.js';
import { relativeToRoot, sha256, toPosixPath } from '../util/impl.js';
import {
  bindingLeaves,
  functionLikeName,
  isFunctionLike,

  lastSegment,
  memberChainOf,
  propertyLabel,
  rangeOfNode,
} from './ast-helpers.js';
import { normalizeLabel } from './label.js';
import type { CallbackLink, SolverHints } from './hints.js';
import type { BuildIROptions, BuildIRResult } from './contract.js';

export type { CallbackLink, SolverHints } from './hints.js';

export interface BuildIRFullResult extends BuildIRResult {
  readonly hints: SolverHints;
}

/** ファイル 1 つぶんの IR 断片。 */
export interface FileIRFragment {
  readonly nodes: readonly FlowNode[];
  readonly edges: readonly FlowEdge[];
  readonly callSites: readonly CallSite[];
  readonly functions: readonly FunctionIR[];
  readonly diagnostics: readonly Diagnostic[];
  readonly hints: SolverHints;
}

/** モジュール直下のコードを表す疑似関数の ID。 */
export const MODULE_SCOPE_ID = '<module>';

interface DeclInfo {
  /** 値ノード。関数宣言のように値を持たない場合は undefined。 */
  readonly nodeId: string | undefined;
  readonly start: number;
  readonly end: number;
}

interface FnCtx {
  readonly functionId: string;
  readonly node: ts.FunctionLikeDeclaration;
  readonly className: string | undefined;
  readonly decls: Map<string, DeclInfo[]>;
  readonly paramNodes: Map<string, string>;
  /** コールバック仮引数ノードを仮引数の順に並べたもの。 */
  readonly paramNodeOrder: string[];
  /** `obj.k = v` の書き込み先（フロー鈍感の補正に使う）。 */
  readonly propertyWrites: Map<string, string>;
  /** `return` 文で作ったノード。 */
  readonly returnNodeIds: string[];
  /** 宣言時に作った値ノード（第 2 段で再利用する）。 */
  readonly valueNodes: Map<ts.Node, string>;
  /** 走査済みかどうか（同じ文脈を 2 度使わない）。 */
  used: boolean;
}

interface PendingCallback {
  readonly callNodeId: string;
  readonly args: readonly { readonly index: number; readonly expression: ts.Expression; readonly nodeId: string }[];
}

/** 1 ファイルぶんの IR を構築する。 */
export function buildFileIR(source: string, relativePath: string, absolutePath: string): FileIRFragment {
  const builder = new FileBuilder(source, relativePath, absolutePath);
  return builder.run();
}

class FileBuilder {
  private readonly sourceFile: ts.SourceFile;
  private readonly nodes: FlowNode[] = [];
  private readonly edges: FlowEdge[] = [];
  private readonly callSites: CallSite[] = [];
  private readonly functions: FunctionIR[] = [];
  private readonly diagnostics: Diagnostic[] = [];
  private readonly callbackLinks = new Map<string, CallbackLink[]>();
  private readonly unresolved = new Set<string>();
  private readonly functionIdByNode = new Map<ts.Node, string>();
  private readonly callees = new Map<string, string[]>();
  /** 関数 ID → 解析文脈。モジュール直下の `<module>` も含む。 */
  private readonly contexts = new Map<string, FnCtx>();
  private readonly moduleFunction: FunctionIR;
  private readonly functionNamesInFile = new Map<string, string>();
  private readonly usedFunctionIds = new Set<string>();
  private readonly pendingCallbacks: PendingCallback[] = [];
  /** 第 2 段で辺を張るための、既定値付き束縛要素。 */
  private readonly pendingDefaults: { readonly nodeId: string; readonly expression: ts.Expression; readonly ctx: FnCtx }[] = [];

  constructor(
    source: string,
    private readonly relativePath: string,
    private readonly absolutePath: string,
  ) {
    this.sourceFile = ts.createSourceFile(absolutePath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
    // モジュール直下のコードも 1 つの関数として扱う。
    // これにより `const app = express()` のような初期化や、
    // トップレベルに置かれたアロー関数も解析対象になる。
    const moduleNode = {
      getStart: () => 0,
      getEnd: () => this.sourceFile.getEnd(),
      body: undefined,
      parameters: [],
      parent: undefined,
    } as unknown as ts.FunctionLikeDeclaration;
    const moduleId = this.createFunctionIR(moduleNode, MODULE_SCOPE_ID, undefined, MODULE_SCOPE_ID);
    const created = this.functionById(moduleId);
    if (created === undefined) {
      throw new Error('internal: モジュール文脈の作成に失敗しました');
    }
    this.moduleFunction = created;
  }

  run(): FileIRFragment {
    this.collectParseDiagnostics();
    this.collectStatements(this.sourceFile.statements, this.moduleFunction.id);
    this.buildBodies();
    this.resolveVariableInitializers();
    this.resolveDefaults();
    this.resolvePendingCallbacks();
    this.linkResolvedReturns();

    // 呼び出し先を確定させてから公開する（構築中は Map へ蓄積している）。
    // モジュール直下の疑似関数は最後に置き、`isModuleScope` で識別できるようにする。
    const finalized = this.functions
      .filter((fn) => fn.id !== MODULE_SCOPE_ID)
      .map((fn) => ({
        ...fn,
        callees: [...(this.callees.get(fn.id) ?? [])].sort(),
      }));
    finalized.push({ ...this.moduleFunction, callees: [...(this.callees.get(MODULE_SCOPE_ID) ?? [])].sort() });

    const links = new Map<string, readonly CallbackLink[]>();
    for (const [key, value] of this.callbackLinks) {
      links.set(key, value);
    }

    return {
      nodes: this.nodes,
      edges: this.edges,
      callSites: this.callSites,
      functions: finalized,
      diagnostics: this.diagnostics,
      hints: { callbackLinks: links, unresolvedCallees: [...this.unresolved].sort() },
    };
  }

  // -------------------------------------------------------------------------
  // ノード・辺の生成
  // -------------------------------------------------------------------------

  private addNode(functionId: string, kind: FlowKind, node: ts.Node, label: string, extra?: Partial<FlowNode>): FlowNode {
    const created: FlowNode = {
      id: `${functionId}#${this.nodes.length}`,
      kind,
      functionId,
      range: rangeOfNode(node, this.sourceFile),
      label: normalizeLabel(label),
      ...extra,
    };
    this.nodes.push(created);
    return created;
  }

  private addEdge(from: string, to: string, kind: FlowEdge['kind'], argIndex?: number): void {
    if (from === to) {
      return;
    }
    this.edges.push(argIndex === undefined ? { from, to, kind } : { from, to, kind, argIndex });
  }

  private addCallee(callerId: string, calleeId: string): void {
    const bucket = this.callees.get(callerId) ?? [];
    if (bucket.includes(calleeId)) {
      return;
    }
    bucket.push(calleeId);
    this.callees.set(callerId, bucket);
  }

  private collectParseDiagnostics(): void {
    const parseDiagnostics = (this.sourceFile as unknown as { parseDiagnostics?: ts.DiagnosticWithLocation[] }).parseDiagnostics;
    if (parseDiagnostics === undefined) {
      return;
    }
    for (const diagnostic of parseDiagnostics.slice(0, 20)) {
      const start = this.sourceFile.getLineAndCharacterOfPosition(diagnostic.start ?? 0);
      this.diagnostics.push({
        level: 'warning',
        message: `構文エラー: ${ts.flattenDiagnosticMessageText(diagnostic.messageText, ' ')}`,
        file: this.absolutePath,
        range: {
          start: { line: start.line + 1, column: start.character + 1 },
          end: { line: start.line + 1, column: start.character + 2 },
        },
      });
    }
  }

  // -------------------------------------------------------------------------
  // 第 1 段: 宣言の収集
  // -------------------------------------------------------------------------

  /**
   * 宣言の収集。`parentId` は所属する関数の ID（モジュール直下は `<module>`）。
   */
  private collectStatements(statements: readonly ts.Statement[], parentId: string): void {
    for (const statement of statements) {
      this.collectStatement(statement, parentId);
    }
  }

  private collectStatement(statement: ts.Statement, parentId: string): void {
    if (ts.isFunctionDeclaration(statement)) {
      if (statement.name !== undefined) {
        this.registerFunction(statement, parentId);
      }
      if (statement.body !== undefined) {
        const id = this.idOf(statement);
        this.collectStatements(statement.body.statements, id ?? parentId);
        return;
      }
    }

    if (isFunctionLike(statement)) {
      this.registerFunction(statement, parentId);
      const body = statement.body;
      if (body !== undefined && ts.isBlock(body)) {
        this.collectStatements(body.statements, this.idOf(statement) ?? parentId);
      }
      return;
    }

    if (ts.isClassDeclaration(statement) || ts.isClassExpression(statement)) {
      this.collectClass(statement, parentId);
      return;
    }

    if (ts.isVariableStatement(statement)) {
      for (const declaration of statement.declarationList.declarations) {
        this.collectVariable(declaration, parentId);
      }
      return;
    }

    if (ts.isBlock(statement)) {
      this.collectStatements(statement.statements, parentId);
      return;
    }

    // 本体を持たない文は子ノードを走査して、入れ子の関数を拾う。
    for (const child of statement.getChildren(this.sourceFile)) {
      this.collectNested(child, parentId);
    }
  }

  /** 入れ子の関数宣言・関数式を再帰的に探して登録する。 */
  private collectNested(node: ts.Node, parentId: string): void {
    if (isFunctionLike(node)) {
      this.registerFunction(node, parentId);
      const body = node.body;
      if (body !== undefined && ts.isBlock(body)) {
        this.collectStatements(body.statements, this.idOf(node) ?? parentId);
      }
      return;
    }
    if (ts.isClassDeclaration(node) || ts.isClassExpression(node)) {
      this.collectClass(node, parentId);
      return;
    }
    for (const child of node.getChildren(this.sourceFile)) {
      this.collectNested(child, parentId);
    }
  }

  private idOf(node: ts.Node): string | undefined {
    return this.functionIdByNode.get(node);
  }

  private collectClass(node: ts.ClassDeclaration | ts.ClassExpression, parentId: string): void {
    for (const member of node.members) {
      if (isFunctionLike(member) && this.contexts.get(parentId)?.functionId !== undefined) {
        this.registerFunction(member, parentId);
      }
    }
  }

  /** 変数宣言の値ノードを作る。初期化式の走査は第 2 段で行う。 */
  private collectVariable(declaration: ts.VariableDeclaration, parentId: string): void {
    const ctx = this.contexts.get(parentId);
    if (ctx === undefined) {
      return;
    }

    const initializer = declaration.initializer;
    const leaves = bindingLeaves(declaration.name);

    // `const f = () => {...}` / `const f = function () {...}`
    if (leaves.length === 1 && initializer !== undefined && (ts.isArrowFunction(initializer) || ts.isFunctionExpression(initializer))) {
      const leaf = leaves[0];
      if (leaf !== undefined) {
        const calleeId = this.registerFunction(initializer, parentId, leaf.name);
        const binding = this.addNode(ctx.functionId, 'local', declaration.name, leaf.name);
        this.pushDecl(ctx, leaf.name, binding.id, declaration);
        this.addCallee(ctx.functionId, calleeId);
        this.boundFunctionByNodeId.set(binding.id, calleeId);
        // ブロック本体なら中身を収集する（式本体は第 2 段で処理する）。
        const body = initializer.body;
        if (ts.isBlock(body)) {
          this.collectStatements(body.statements, calleeId);
        }
        this.variableDeclarations.push({ declaration, ctx, nodes: [binding.id] });
        return;
      }
    }

    const nodes: string[] = [];
    for (const leaf of leaves) {
      const label = leaf.path.length > 0 ? leaf.path.join('.') : leaf.name;
      const kind: FlowKind = leaf.path.length > 0 ? 'property' : 'local';
      const node = this.addNode(ctx.functionId, kind, leaf.node, label);
      nodes.push(node.id);
      ctx.valueNodes.set(leaf.node, node.id);
      this.pushDecl(ctx, leaf.name, node.id, declaration);
      if (leaf.initializer !== undefined) {
        this.pendingDefaults.push({ nodeId: node.id, expression: leaf.initializer, ctx });
      }
    }
    this.variableDeclarations.push({ declaration, ctx, nodes });
  }

  private readonly variableDeclarations: { declaration: ts.VariableDeclaration; ctx: FnCtx; nodes: string[] }[] = [];

  private pushDecl(ctx: FnCtx, name: string, nodeId: string | undefined, declaration: ts.Node): void {
    this.pushDeclAt(ctx, name, nodeId, declaration.getStart(this.sourceFile), declaration.getEnd());
  }

  private pushDeclAt(ctx: FnCtx, name: string, nodeId: string | undefined, start: number, end: number): void {
    const entries = ctx.decls.get(name) ?? [];
    entries.push({ nodeId, start, end });
    ctx.decls.set(name, entries);
  }

  /**
   * 関数を登録する。IR エントリと仮引数ノードを作り、文脈を登録する。
   * 同じ AST ノードには冪等。
   */
  private registerFunction(node: ts.FunctionLikeDeclaration, _parentId: string, nameHint?: string): string {
    const existing = this.functionIdByNode.get(node);
    if (existing !== undefined) {
      return existing;
    }
    return this.createFunctionIR(node, '', this.classNameOfFunction(node) ?? this.classNameOfParentId(_parentId), nameHint);
  }

  private classNameOfParentId(parentId: string): string | undefined {
    return this.contexts.get(parentId)?.className;
  }

  /** 構文ノードから所属クラス名を求める（メソッド宣言で使う）。 */
  private classNameOfFunction(node: ts.FunctionLikeDeclaration): string | undefined {
    let current: ts.Node | undefined = node.parent;
    while (current !== undefined) {
      if (ts.isClassDeclaration(current) || ts.isClassExpression(current)) {
        return current.name?.text;
      }
      if (isFunctionLike(current)) {
        return undefined;
      }
      current = current.parent;
    }
    return undefined;
  }

  private functionById(id: string): FunctionIR | undefined {
    return this.functions.find((fn) => fn.id === id);
  }

  /**
   * 関数の IR と解析文脈を作る。
   * `registerFunction` は AST ノードがある場合、こちらはモジュール直下のように
   * 対応する構文ノードを持たない疑似関数にも使う。
   */
  private createFunctionIR(
    node: ts.FunctionLikeDeclaration,
    syntheticId: string,
    className: string | undefined,
    nameHint?: string,
  ): string {
    const inferred = this.inferNameFromParent(node);
    const rawName = nameHint ?? functionLikeName(node) ?? inferred ?? 'anonymous';
    const isModule = syntheticId === MODULE_SCOPE_ID;
    const functionId = isModule ? MODULE_SCOPE_ID : this.uniqueFunctionId(className === undefined ? rawName : `${className}.${rawName}`);

    const params: ParamIR[] = [];
    for (const parameter of node.parameters) {
      const leaves = bindingLeaves(parameter.name);
      const optional = parameter.initializer !== undefined || parameter.questionToken !== undefined;
      const rest = parameter.dotDotDotToken !== undefined;
      if (leaves.length === 0) {
        params.push({ name: `arg${params.length}`, index: params.length, optional, rest });
        continue;
      }
      for (const leaf of leaves) {
        params.push({
          name: leaf.name,
          index: params.length,
          optional,
          rest,
          ...(leaf.path.length > 0 ? { destructured: leaf.path } : {}),
        });
      }
    }

    const bodyRange = node.body === undefined ? rangeOfNode(node, this.sourceFile) : rangeOfNode(node.body, this.sourceFile);
    const ir: FunctionIR = {
      id: functionId,
      name: rawName,
      ...(className === undefined ? {} : { className }),
      file: this.absolutePath,
      range: rangeOfNode(node, this.sourceFile),
      params,
      bodyRange,
      callees: [],
      analysable: isModule ? true : node.body !== undefined,
      // モジュール直下は「関数」ではないが、初期化コードを解析するために 1 つの
      // スコープとして扱う。レポートから除外できるようフラグを立てる。
      ...(isModule ? { isModuleScope: true } : {}),
    };
    this.functions.push(ir);
    this.functionIdByNode.set(node, functionId);
    if (!rawName.includes('.')) {
      this.functionNamesInFile.set(rawName, functionId);
    }

    const ctx: FnCtx = {
      functionId,
      node,
      className,
      decls: new Map(),
      paramNodes: new Map(),
      paramNodeOrder: [],
      propertyWrites: new Map(),
      returnNodeIds: [],
      valueNodes: new Map(),
      used: false,
    };

    // 仮引数のノード。ここが関数内データフローの入口。
    let argIndex = 0;
    for (const parameter of node.parameters) {
      const leaves = bindingLeaves(parameter.name);
      if (leaves.length === 0) {
        const created = this.addNode(functionId, 'param', parameter, `arg${argIndex}`);
        ctx.paramNodeOrder.push(created.id);
        ctx.paramNodes.set(`arg${argIndex}`, created.id);
        argIndex += 1;
        continue;
      }
      for (const leaf of leaves) {
        const label = leaf.path.length > 0 ? `${leaf.name}: ${leaf.path.join('.')}` : leaf.name;
        const kind: FlowKind = leaf.path.length > 0 ? 'property' : 'param';
        const created = this.addNode(functionId, kind, leaf.node, label);
        ctx.paramNodeOrder.push(created.id);
        ctx.paramNodes.set(leaf.name, created.id);
        // 仮引数の宣言位置は「識別子そのもの」を使う。
        // 型注釈を含む範囲で登録すると、以降の読み出しが一致しなくなる。
        this.pushDeclAt(ctx, leaf.name, created.id, leaf.node.getStart(this.sourceFile), leaf.node.getEnd());
        argIndex += 1;
      }
    }

    this.contexts.set(functionId, ctx);
    return functionId;
  }

  /**
   * 親ノードから関数の表示名を推測する。
   *
   * 変数束縛（`const f = () => {}`）は変数名を、コールバック
   * （`db.query(sql, cb)`）は `db.query~arg1` のような呼び出し文脈の名前を付ける。
   * レポートに `anonymous` が並ぶのを避けるための工夫。
   */
  private inferNameFromParent(node: ts.FunctionLikeDeclaration): string | undefined {
    let current: ts.Node = node;
    let parent: ts.Node | undefined = node.parent;
    while (
      parent !== undefined &&
      (ts.isParenthesizedExpression(parent) ||
        ts.isAsExpression(parent) ||
        ts.isAwaitExpression(parent) ||
        ts.isSpreadElement(parent))
    ) {
      current = parent;
      parent = parent.parent;
    }
    if (parent === undefined) {
      return undefined;
    }
    if (ts.isVariableDeclaration(parent) && ts.isIdentifier(parent.name)) {
      return parent.name.text;
    }
    if (ts.isPropertyAssignment(parent)) {
      return parent.name.getText(this.sourceFile);
    }
    if (ts.isBinaryExpression(parent) && ts.isIdentifier(parent.left)) {
      return parent.left.text;
    }
    if (ts.isCallExpression(parent) || ts.isNewExpression(parent)) {
      const callee = memberChainOf(parent.expression) ?? parent.expression.getText(this.sourceFile);
      const args = parent.arguments;
      if (args !== undefined) {
        const position = args.indexOf(current as ts.Expression);
        if (position >= 0) {
          return `${callee}~arg${position}`;
        }
      }
      return `${callee}~callback`;
    }
    return undefined;
  }

  private uniqueFunctionId(base: string): string {
    const prefix = `${this.relativePath}::`;
    let candidate = `${prefix}${base}`;
    let counter = 2;
    while (this.usedFunctionIds.has(candidate)) {
      candidate = `${prefix}${base}~${counter}`;
      counter += 1;
    }
    this.usedFunctionIds.add(candidate);
    return candidate;
  }

  // -------------------------------------------------------------------------
  // 第 2 段: 本体の走査
  // -------------------------------------------------------------------------

  private buildBodies(): void {
    for (const ctx of this.contexts.values()) {
      if (ctx.used) {
        continue;
      }
      ctx.used = true;
      this.buildBody(ctx);
    }
  }

  /** 1 つの関数本体（ブロックまたは式）を走査する。 */
  private buildBody(ctx: FnCtx): void {
    const body = ctx.node.body;
    if (body === undefined) {
      return;
    }
    if (ts.isBlock(body)) {
      for (const statement of body.statements) {
        this.statement(statement, ctx);
      }
      return;
    }
    const value = this.expression(body, ctx);
    if (value !== undefined) {
      this.recordReturn(value, ctx);
    }
  }

  /**
   * 変数宣言の初期化子を、束縛されたすべての変数へ結ぶ。
   *
   * `const { a, b } = req.query` は `req.query` から `a`・`b` の両方へ流れる。
   * 単純な `const x = v` もここで 1 本の辺になる。
   */
  private resolveVariableInitializers(): void {
    for (const entry of this.variableDeclarations) {
      const initializer = entry.declaration.initializer;
      if (initializer === undefined) {
        continue;
      }
      const value = this.expression(initializer, entry.ctx);
      if (value === undefined) {
        continue;
      }
      for (const nodeId of entry.nodes) {
        this.addEdge(value, nodeId, 'assign');
      }
    }
  }

  private resolveDefaults(): void {
    // 分割代入の既定値（`const { a = req.query.x } = req.body`）
    for (const pending of this.pendingDefaults) {
      const value = this.expression(pending.expression, pending.ctx);
      if (value !== undefined) {
        this.addEdge(value, pending.nodeId, 'assign');
      }
    }
    this.pendingDefaults.length = 0;

    // 仮引数の既定値（`function f(a = req.query.x)`）
    for (const [, ctx] of this.contexts) {
      for (const parameter of ctx.node.parameters) {
        if (parameter.initializer === undefined) {
          continue;
        }
        const value = this.expression(parameter.initializer, ctx);
        if (value === undefined) {
          continue;
        }
        for (const leaf of bindingLeaves(parameter.name)) {
          const target = ctx.paramNodes.get(leaf.name);
          if (target !== undefined) {
            this.addEdge(value, target, 'assign');
          }
        }
      }
    }
  }

  private recordReturn(value: string, ctx: FnCtx): void {
    const returnNode = this.addNode(ctx.functionId, 'return', ctx.node, 'return');
    ctx.returnNodeIds.push(returnNode.id);
    this.addEdge(value, returnNode.id, 'return');
  }

  /** 前方参照を許す宣言解決。 */
  private bestDecl(ctx: FnCtx, name: string, position: number): DeclInfo | undefined {
    const entries = ctx.decls.get(name);
    if (entries === undefined) {
      return undefined;
    }
    let preceding: DeclInfo | undefined;
    let earliest: DeclInfo | undefined;
    for (const entry of entries) {
      if (earliest === undefined || entry.start < earliest.start) {
        earliest = entry;
      }
      if (entry.end <= position && (preceding === undefined || entry.start > preceding.start)) {
        preceding = entry;
      }
    }
    return preceding ?? earliest;
  }

  private statement(statement: ts.Statement, ctx: FnCtx): void {
    if (ts.isExpressionStatement(statement)) {
      this.expression(statement.expression, ctx);
      return;
    }

    if (ts.isVariableStatement(statement)) {
      // 変数宣言の初期化子は `resolveVariableInitializers()` が一度だけ走査する。
      // ここで再度走査すると、同じ AST に対してノードと辺が二重に作られる。
      return;
    }

    if (ts.isReturnStatement(statement)) {
      if (statement.expression !== undefined) {
        const value = this.expression(statement.expression, ctx);
        if (value !== undefined) {
          this.recordReturn(value, ctx);
        }
      }
      return;
    }

    if (ts.isIfStatement(statement)) {
      this.expression(statement.expression, ctx);
      this.statement(statement.thenStatement, ctx);
      if (statement.elseStatement !== undefined) {
        this.statement(statement.elseStatement, ctx);
      }
      return;
    }

    if (ts.isBlock(statement)) {
      for (const inner of statement.statements) {
        this.statement(inner, ctx);
      }
      return;
    }

    if (ts.isForStatement(statement)) {
      const initializer = statement.initializer;
      if (initializer !== undefined) {
        if (ts.isVariableDeclarationList(initializer)) {
          // 初期化子は `resolveVariableInitializers()` が担当する。
          void initializer;
        } else {
          this.expression(initializer, ctx);
        }
      }
      if (statement.condition !== undefined) {
        this.expression(statement.condition, ctx);
      }
      if (statement.incrementor !== undefined) {
        this.expression(statement.incrementor, ctx);
      }
      this.statement(statement.statement, ctx);
      return;
    }

    if (ts.isForOfStatement(statement) || ts.isForInStatement(statement)) {
      const value = this.expression(statement.expression, ctx);
      const initializer = statement.initializer;
      if (ts.isVariableDeclarationList(initializer)) {
        for (const declaration of initializer.declarations) {
          for (const leaf of bindingLeaves(declaration.name)) {
            const node = this.addNode(ctx.functionId, 'local', leaf.node, leaf.name);
            this.pushDecl(ctx, leaf.name, node.id, declaration);
            if (value !== undefined) {
              this.addEdge(value, node.id, 'assign');
            }
          }
        }
      } else {
        const target = this.writeTarget(initializer, ctx);
        if (value !== undefined && target !== undefined) {
          this.addEdge(value, target, 'assign');
        }
      }
      this.statement(statement.statement, ctx);
      return;
    }

    if (ts.isWhileStatement(statement) || ts.isDoStatement(statement)) {
      this.expression(statement.expression, ctx);
      this.statement(statement.statement, ctx);
      return;
    }

    if (ts.isTryStatement(statement)) {
      this.statement(statement.tryBlock, ctx);
      if (statement.catchClause !== undefined) {
        this.statement(statement.catchClause.block, ctx);
      }
      if (statement.finallyBlock !== undefined) {
        this.statement(statement.finallyBlock, ctx);
      }
      return;
    }

    if (ts.isSwitchStatement(statement)) {
      this.expression(statement.expression, ctx);
      for (const clause of statement.caseBlock.clauses) {
        for (const inner of clause.statements) {
          this.statement(inner, ctx);
        }
      }
      return;
    }

    if (ts.isThrowStatement(statement)) {
      if (statement.expression !== undefined) {
        this.expression(statement.expression, ctx);
      }
      return;
    }

    if (ts.isLabeledStatement(statement)) {
      this.statement(statement.statement, ctx);
      return;
    }

    if (ts.isWithStatement(statement)) {
      this.expression(statement.expression, ctx);
      this.statement(statement.statement, ctx);
    }
  }

  /**
   * 代入先（書き込み対象）のノード ID を返す。
   *
   * `presetId` は「左辺を式として読んだ結果」のノード。`obj.k += v` のように
   * 左辺を値としても使う場合、同じノードを使い回す。再評価すると
   * ノードが重複し、`o → o` のような自己辺ができてしまう。
   */
  private writeTarget(target: ts.Expression, ctx: FnCtx, presetId?: string | undefined): string | undefined {
    if (ts.isIdentifier(target)) {
      const decl = this.bestDecl(ctx, target.text, target.getStart(this.sourceFile));
      if (decl?.nodeId !== undefined) {
        return decl.nodeId;
      }
      const param = ctx.paramNodes.get(target.text);
      if (param !== undefined) {
        return param;
      }
      const created = this.addNode(ctx.functionId, 'local', target, target.text);
      this.pushDecl(ctx, target.text, created.id, target);
      return created.id;
    }

    if (ts.isPropertyAccessExpression(target) || ts.isElementAccessExpression(target)) {
      const label = propertyLabel(target, this.sourceFile);
      if (presetId !== undefined) {
        // 左辺を既に値として読んでいる場合は、そのノードを書き込み先として使う。
        ctx.propertyWrites.set(label, presetId);
        return presetId;
      }
      const baseId = this.expression(target.expression, ctx);
      const node = this.addNode(ctx.functionId, 'property', target, label);
      if (baseId !== undefined) {
        this.addEdge(baseId, node.id, 'property');
      }
      if (ts.isElementAccessExpression(target)) {
        const keyValue = this.expression(target.argumentExpression, ctx);
        if (keyValue !== undefined) {
          this.addEdge(keyValue, node.id, 'property');
        }
      }
      ctx.propertyWrites.set(label, node.id);
      return node.id;
    }

    if (ts.isObjectLiteralExpression(target) || ts.isArrayLiteralExpression(target)) {
      return this.expression(target, ctx);
    }

    return this.expression(target, ctx);
  }

  // -------------------------------------------------------------------------
  // 式
  // -------------------------------------------------------------------------

  private expression(expression: ts.Expression, ctx: FnCtx): string | undefined {
    if (ts.isIdentifier(expression)) {
      return this.identifier(expression, ctx);
    }

    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      return this.propertyRead(expression, ctx);
    }

    if (ts.isCallExpression(expression) || ts.isNewExpression(expression)) {
      return this.callExpression(expression, ctx);
    }

    if (ts.isTemplateExpression(expression)) {
      return this.templateExpression(expression, ctx);
    }

    if (ts.isBinaryExpression(expression)) {
      return this.binaryExpression(expression, ctx);
    }

    if (ts.isStringLiteralLike(expression) || ts.isNumericLiteral(expression) || ts.isNoSubstitutionTemplateLiteral(expression)) {
      return this.addNode(ctx.functionId, 'literal', expression, expression.getText(this.sourceFile)).id;
    }

    // `this` はレシーバとして重要（`this.db.query(...)` の解決に使う）。
    // unknown に落とすと診断が埋まり、レシーバも追えなくなる。
    if (expression.kind === ts.SyntaxKind.ThisKeyword) {
      return this.addNode(ctx.functionId, 'local', expression, 'this').id;
    }

    // 正規表現リテラルは値を持つ。パターン自体を汚染として扱う必要はない。
    if (ts.isRegularExpressionLiteral(expression)) {
      return this.addNode(ctx.functionId, 'literal', expression, expression.getText(this.sourceFile)).id;
    }

    // `import.meta` / `new.target` も値として扱う。
    if (ts.isMetaProperty(expression)) {
      return this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile)).id;
    }

    if (
      expression.kind === ts.SyntaxKind.TrueKeyword ||
      expression.kind === ts.SyntaxKind.FalseKeyword ||
      expression.kind === ts.SyntaxKind.NullKeyword ||
      expression.kind === ts.SyntaxKind.UndefinedKeyword
    ) {
      return this.addNode(ctx.functionId, 'literal', expression, expression.getText(this.sourceFile)).id;
    }

    if (ts.isParenthesizedExpression(expression) || ts.isNonNullExpression(expression)) {
      return this.expression(expression.expression, ctx);
    }

    if (ts.isAsExpression(expression) || ts.isTypeAssertionExpression(expression) || ts.isSatisfiesExpression(expression)) {
      return this.expression(expression.expression, ctx);
    }

    if (ts.isConditionalExpression(expression)) {
      const parts = [
        this.expression(expression.condition, ctx),
        this.expression(expression.whenTrue, ctx),
        this.expression(expression.whenFalse, ctx),
      ];
      const node = this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile));
      for (const part of parts) {
        if (part !== undefined) {
          this.addEdge(part, node.id, 'assign');
        }
      }
      return node.id;
    }

    if (ts.isArrayLiteralExpression(expression)) {
      const node = this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile));
      for (const element of expression.elements) {
        const value = ts.isSpreadElement(element) ? this.expression(element.expression, ctx) : this.expression(element, ctx);
        if (value !== undefined) {
          this.addEdge(value, node.id, 'assign');
        }
      }
      return node.id;
    }

    if (ts.isObjectLiteralExpression(expression)) {
      const node = this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile));
      for (const property of expression.properties) {
        if (ts.isPropertyAssignment(property)) {
          const value = this.expression(property.initializer, ctx);
          if (value !== undefined) {
            this.addEdge(value, node.id, 'property');
          }
        } else if (ts.isShorthandPropertyAssignment(property)) {
          const value = this.identifier(property.name, ctx);
          if (value !== undefined) {
            this.addEdge(value, node.id, 'property');
          }
        } else if (ts.isSpreadAssignment(property)) {
          const value = this.expression(property.expression, ctx);
          if (value !== undefined) {
            this.addEdge(value, node.id, 'property');
          }
        }
      }
      return node.id;
    }

    if (ts.isAwaitExpression(expression)) {
      const inner = this.expression(expression.expression, ctx);
      const node = this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile));
      if (inner !== undefined) {
        this.addEdge(inner, node.id, 'assign');
      }
      return node.id;
    }

    if (ts.isVoidExpression(expression)) {
      this.expression(expression.expression, ctx);
      return undefined;
    }

    if (ts.isArrowFunction(expression) || ts.isFunctionExpression(expression)) {
      // コールバックとして渡される関数式は、呼び出し側の配線で扱う。
      if (!this.functionIdByNode.has(expression)) {
        this.registerFunction(expression, ctx.functionId);
      }
      const registered = this.functionIdByNode.get(expression);
      const inner = registered === undefined ? undefined : this.contexts.get(registered);
      if (inner !== undefined && !inner.used) {
        inner.used = true;
        this.buildBody(inner);
      }
      return undefined;
    }

    if (ts.isTypeOfExpression(expression) || ts.isDeleteExpression(expression)) {
      return this.addNode(ctx.functionId, 'literal', expression, expression.getText(this.sourceFile)).id;
    }

    if (ts.isPostfixUnaryExpression(expression) || ts.isPrefixUnaryExpression(expression)) {
      return this.expression(expression.operand, ctx);
    }

    if (ts.isClassExpression(expression)) {
      // クラス式はメソッドのみを登録済み。値としては扱わない。
      return undefined;
    }

    const node = this.addNode(ctx.functionId, 'unknown', expression, expression.getText(this.sourceFile));
    this.diagnostics.push({
      level: 'info',
      message: `未対応の式構文を unknown ノードとして扱いました: ${ts.SyntaxKind[expression.kind]}`,
      file: this.absolutePath,
      range: rangeOfNode(expression, this.sourceFile),
    });
    return node.id;
  }

  private identifier(expression: ts.Identifier, ctx: FnCtx): string | undefined {
    const decl = this.bestDecl(ctx, expression.text, expression.getStart(this.sourceFile));
    if (decl?.nodeId !== undefined) {
      return decl.nodeId;
    }
    const param = ctx.paramNodes.get(expression.text);
    if (param !== undefined) {
      return param;
    }
    if (this.functionNamesInFile.has(expression.text)) {
      return undefined;
    }
    return this.addNode(ctx.functionId, 'global', expression, expression.text).id;
  }

  private propertyRead(expression: ts.PropertyAccessExpression | ts.ElementAccessExpression, ctx: FnCtx): string | undefined {
    const base = expression.expression;
    const baseId =
      ts.isIdentifier(base) && this.functionNamesInFile.has(base.text) ? undefined : this.expression(base, ctx);
    const label = propertyLabel(expression, this.sourceFile);
    const node = this.addNode(ctx.functionId, 'property', expression, label);

    if (baseId !== undefined) {
      this.addEdge(baseId, node.id, 'property');
    }
    if (ts.isElementAccessExpression(expression)) {
      // `o[key]` の結果は、鍵が汚染されていれば汚染される（プロトタイプ汚染・
      // 動的キー経由の注入を捕まえるため、鍵からの辺も張る）。
      const keyValue = this.expression(expression.argumentExpression, ctx);
      if (keyValue !== undefined) {
        this.addEdge(keyValue, node.id, 'property');
      }
    }

    const written = ctx.propertyWrites.get(label);
    if (written !== undefined) {
      this.addEdge(written, node.id, 'assign');
    }
    return node.id;
  }

  private templateExpression(expression: ts.TemplateExpression, ctx: FnCtx): string {
    const node = this.addNode(ctx.functionId, 'template', expression, expression.getText(this.sourceFile));
    for (const span of expression.templateSpans) {
      const value = this.expression(span.expression, ctx);
      if (value !== undefined) {
        this.addEdge(value, node.id, 'assign');
      }
    }
    return node.id;
  }

  private binaryExpression(expression: ts.BinaryExpression, ctx: FnCtx): string | undefined {
    const operator = expression.operatorToken.kind;

    if (operator === ts.SyntaxKind.EqualsToken || operator === ts.SyntaxKind.QuestionQuestionEqualsToken) {
      const right = this.expression(expression.right, ctx);
      const target = this.writeTarget(expression.left, ctx);
      if (right !== undefined && target !== undefined) {
        this.addEdge(right, target, 'assign');
      }
      // `x = helper` のように関数を変数へ束縛する代入を記録する。
      if (target !== undefined && right !== undefined) {
        const fnId = this.functionReferenceId(expression.right);
        if (fnId !== undefined) {
          this.boundFunctionByNodeId.set(target, fnId);
        }
      }
      return target;
    }

    if (operator === ts.SyntaxKind.PlusToken || operator === ts.SyntaxKind.MinusToken) {
      const left = this.expression(expression.left, ctx);
      const right = this.expression(expression.right, ctx);
      const node = this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile));
      for (const part of [left, right]) {
        if (part !== undefined) {
          this.addEdge(part, node.id, 'assign');
        }
      }
      return node.id;
    }

    if (
      operator === ts.SyntaxKind.PlusEqualsToken ||
      operator === ts.SyntaxKind.MinusEqualsToken ||
      operator === ts.SyntaxKind.BarBarEqualsToken ||
      operator === ts.SyntaxKind.AmpersandAmpersandEqualsToken
    ) {
      const left = this.expression(expression.left, ctx);
      const right = this.expression(expression.right, ctx);
      const target = this.writeTarget(expression.left, ctx);
      if (target !== undefined) {
        for (const part of [left, right]) {
          if (part !== undefined) {
            this.addEdge(part, target, 'assign');
          }
        }
      }
      return target;
    }

    const left = this.expression(expression.left, ctx);
    const right = this.expression(expression.right, ctx);
    const node = this.addNode(ctx.functionId, 'local', expression, expression.getText(this.sourceFile));
    for (const part of [left, right]) {
      if (part !== undefined) {
        this.addEdge(part, node.id, 'assign');
      }
    }
    return node.id;
  }

  private callExpression(expression: ts.CallExpression | ts.NewExpression, ctx: FnCtx): string | undefined {
    const calleeText = expression.expression.getText(this.sourceFile);
    const chain = memberChainOf(expression.expression);
    const calleeIds = this.resolveCallees(expression.expression, chain, ctx);

    const args: { index: number; expression: ts.Expression; nodeId: string }[] = [];
    let index = 0;
    for (const argument of expression.arguments ?? []) {
      const value = ts.isSpreadElement(argument) ? this.expression(argument.expression, ctx) : this.expression(argument, ctx);
      if (value !== undefined) {
        args.push({ index, expression: ts.isSpreadElement(argument) ? argument.expression : argument, nodeId: value });
      }
      index += 1;
    }

    const node = this.addNode(ctx.functionId, 'call', expression, calleeText, {
      ...(calleeIds.length > 0 ? { resolvedCallees: calleeIds } : {}),
      text: normalizeLabel(expression.getText(this.sourceFile)),
    });

    for (const argument of args) {
      this.addEdge(argument.nodeId, node.id, 'argument', argument.index);
    }
    for (const calleeId of calleeIds) {
      this.addCallee(ctx.functionId, calleeId);
    }

    if (calleeIds.length === 0) {
      const name = chain ?? lastSegment(calleeText);
      if (name !== undefined) {
        this.unresolved.add(name);
      }
    }

    this.callSites.push({
      nodeId: node.id,
      callerId: ctx.functionId,
      calleeIds,
      text: normalizeLabel(calleeText),
      range: rangeOfNode(expression, this.sourceFile),
    });

    if (args.length > 0) {
      this.pendingCallbacks.push({ callNodeId: node.id, args });
    }
    return node.id;
  }

  private resolveCallees(callee: ts.Expression, chain: string | undefined, ctx: FnCtx): string[] {
    if (ts.isIdentifier(callee)) {
      const local = this.functionNamesInFile.get(callee.text);
      if (local !== undefined) {
        return [local];
      }
      const decl = this.bestDecl(ctx, callee.text, callee.getStart(this.sourceFile));
      if (decl?.nodeId !== undefined) {
        const bound = this.functions.find((fn) => fn.id === this.boundFunctionByNodeId.get(decl.nodeId ?? ''));
        if (bound !== undefined) {
          return [bound.id];
        }
      }
      return [];
    }

    if (chain !== undefined) {
      const segments = chain.split('.');
      const method = segments[segments.length - 1];
      if (method !== undefined && segments[0] === 'this' && ctx.className !== undefined) {
        const candidate = `${this.relativePath}::${ctx.className}.${method}`;
        if (this.usedFunctionIds.has(candidate)) {
          return [candidate];
        }
      }
      if (method !== undefined) {
        const matches = this.functions.filter((fn) => fn.name === method).map((fn) => fn.id);
        if (matches.length === 1) {
          return matches;
        }
      }
    }
    return [];
  }

  /** 変数束縛された関数式のノード ID → 関数 ID。 */
  private readonly boundFunctionByNodeId = new Map<string, string>();

  private resolvePendingCallbacks(): void {
    for (const pending of this.pendingCallbacks) {
      const pairs: { argNodeId: string; paramNodeId: string }[] = [];
      let returnNodeId: string | undefined;

      for (const argument of pending.args) {
        const callbackId = this.callbackFunctionId(argument.expression);
        if (callbackId === undefined) {
          continue;
        }
        const params = this.nodes.filter((node) => node.functionId === callbackId && node.kind === 'param');
        const target = params[argument.index];
        if (target !== undefined) {
          pairs.push({ argNodeId: argument.nodeId, paramNodeId: target.id });
        }
        const returns = this.nodes.filter((node) => node.functionId === callbackId && node.kind === 'return');
        const last = returns[returns.length - 1];
        if (last !== undefined) {
          returnNodeId = last.id;
        }
      }

      if (pairs.length === 0 && returnNodeId === undefined) {
        continue;
      }

      const bucket = this.callbackLinks.get(pending.callNodeId) ?? [];
      bucket.push({
        callNodeId: pending.callNodeId,
        pairs,
        ...(returnNodeId === undefined ? {} : { returnNodeId }),
      });
      this.callbackLinks.set(pending.callNodeId, bucket);

      if (returnNodeId !== undefined) {
        this.addEdge(returnNodeId, pending.callNodeId, 'return');
      }
    }
    this.pendingCallbacks.length = 0;
  }

  /**
   * 関数を参照している式（`helper`、`obj.method`、`this.m`）から関数 ID を求める。
   * `const h = helper` のような別名束縛を解決するために使う。
   */
  private functionReferenceId(expression: ts.Expression): string | undefined {
    if (ts.isIdentifier(expression)) {
      const named = this.functionNamesInFile.get(expression.text);
      if (named !== undefined) {
        return named;
      }
      return undefined;
    }
    if (ts.isPropertyAccessExpression(expression) || ts.isElementAccessExpression(expression)) {
      const chain = memberChainOf(expression);
      const method = chain === undefined ? undefined : chain.split('.').pop();
      if (method === undefined) {
        return undefined;
      }
      const matches = this.functions.filter((fn) => fn.name === method).map((fn) => fn.id);
      return matches.length === 1 ? matches[0] : undefined;
    }
    return undefined;
  }

  /**
   * 解決済みの静的呼び出しに対し、呼び出し先の `return` から呼び出し式へ辺を張る。
   *
   * これにより「戻り値をそのまま受け取る」形の伝播が IR だけで閉じる。
   * サマリを使う解析エンジンは、この辺を補強として利用できる。
   */
  private linkResolvedReturns(): void {
    for (const site of this.callSites) {
      if (site.calleeIds.length === 0) {
        continue;
      }
      for (const calleeId of site.calleeIds) {
        const ctx = this.contexts.get(calleeId);
        if (ctx === undefined) {
          continue;
        }
        // `return node` は kind === 'return' のノードなので、関数内の値を取り出す。
        const returns = this.nodes.filter((node) => node.functionId === calleeId && node.kind === 'return');
        for (const returnNode of returns) {
          this.addEdge(returnNode.id, site.nodeId, 'return');
        }
      }
    }
  }

  private callbackFunctionId(expression: ts.Expression): string | undefined {
    const direct = this.functionIdByNode.get(expression);
    if (direct !== undefined) {
      return direct;
    }
    if (ts.isIdentifier(expression)) {
      const named = this.functionNamesInFile.get(expression.text);
      if (named !== undefined) {
        return named;
      }
    }
    if (ts.isParenthesizedExpression(expression)) {
      return this.callbackFunctionId(expression.expression);
    }
    return undefined;
  }
}

/** 実ファイル群を読み込んで 1 つの IRGraph を構築する。 */
export async function buildIR(options: BuildIROptions): Promise<BuildIRFullResult> {
  const files = [...options.files].sort();
  const nodes: FlowNode[] = [];
  const edges: FlowEdge[] = [];
  const callSites: CallSite[] = [];
  const functions: FunctionIR[] = [];
  const diagnostics: Diagnostic[] = [];
  const fileInfos: SourceFileInfo[] = [];
  const callbackLinks = new Map<string, readonly CallbackLink[]>();
  const unresolved = new Set<string>();
  const hashLength = options.hashLength ?? 16;
  const total = files.length;

  options.onProgress?.({ phase: 'parse', current: 0, total });

  for (const [index, file] of files.entries()) {
    let source: string;
    try {
      source = await readFile(file, 'utf8');
    } catch (error) {
      diagnostics.push({
        level: 'error',
        message: `ファイルを読み込めませんでした: ${error instanceof Error ? error.message : String(error)}`,
        file,
      });
      continue;
    }

    const relativePath = relativeToRoot(options.root, file);
    const fragment = buildFileIR(source, relativePath, file);

    nodes.push(...fragment.nodes);
    edges.push(...fragment.edges);
    callSites.push(...fragment.callSites);
    functions.push(...fragment.functions);
    diagnostics.push(...fragment.diagnostics);
    for (const [key, value] of fragment.hints.callbackLinks) {
      callbackLinks.set(key, value);
    }
    for (const name of fragment.hints.unresolvedCallees) {
      unresolved.add(name);
    }

    fileInfos.push({
      path: file,
      relativePath: toPosixPath(relativePath),
      hash: sha256(source, hashLength),
      lineCount: source.split('\n').length,
    });

    options.onProgress?.({ phase: 'parse', current: index + 1, total, detail: relativePath });
  }

  const functionsByFile = new Map<string, string[]>();
  for (const fn of functions) {
    const bucket = functionsByFile.get(fn.file) ?? [];
    bucket.push(fn.id);
    functionsByFile.set(fn.file, bucket);
  }

  const graph: IRGraph = {
    functions,
    nodes,
    edges,
    callSites,
    functionsByFile,
    nodeById: new Map(nodes.map((node) => [node.id, node])),
    functionById: new Map(functions.map((fn) => [fn.id, fn])),
  };

  return {
    graph,
    files: fileInfos,
    diagnostics,
    hints: { callbackLinks, unresolvedCallees: [...unresolved].sort() },
  };
}

/** ソース断片から IR を構築する（テスト・埋め込み用）。 */
export function buildIRFromSource(source: string, relativePath: string, options?: { readonly root?: string }): IRGraph {
  const root = toPosixPath(options?.root ?? process.cwd());
  const absolutePath = `${root}/${toPosixPath(relativePath)}`;
  const fragment = buildFileIR(source, relativePath, absolutePath);
  const functionsByFile = new Map<string, string[]>();
  for (const fn of fragment.functions) {
    const bucket = functionsByFile.get(fn.file) ?? [];
    bucket.push(fn.id);
    functionsByFile.set(fn.file, bucket);
  }
  return {
    functions: fragment.functions,
    nodes: fragment.nodes,
    edges: fragment.edges,
    callSites: fragment.callSites,
    functionsByFile,
    nodeById: new Map(fragment.nodes.map((node) => [node.id, node])),
    functionById: new Map(fragment.functions.map((fn) => [fn.id, fn])),
  };
}

/** `file.ts::Class.method` 形式の関数 ID を組み立てる。 */
export function makeFunctionId(relativePath: string, className: string | undefined, name: string): string {
  const base = className === undefined ? name : `${className}.${name}`;
  return `${toPosixPath(relativePath)}::${base}`;
}

/** 空の IR グラフ（テストの初期値に使う）。 */
export function emptyIRGraph(): IRGraph {
  return {
    functions: [],
    nodes: [],
    edges: [],
    callSites: [],
    functionsByFile: new Map(),
    nodeById: new Map(),
    functionById: new Map(),
  };
}

export type { BuildIROptions, BuildIRResult } from './contract.js';
