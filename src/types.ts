/**
 * 公開型定義 — shirokuma-sast のモジュール間コントラクト。
 *
 * ここに定義された型はパイプラインの各段が共有する唯一の境界面である。
 *   parse → IR 構築 → ルール合成 → データフロー解析 → 検出 → レポート
 *
 * 設計方針:
 * - すべての構造は JSON へ決定的にシリアライズできる（キー順に依存しない）。
 * - 位置情報は 1-based の行・列で保持し、SARIF の region 仕様と一致させる。
 * - 解析結果は「なぜ脆弱と判定したか」を必ず説明できる形で持つ（proof）。
 */

/** 検出の重要度。CVSS ではなく、修正優先度を伝えるためのラベル。 */
export type Severity = 'error' | 'warning' | 'note';

/** データフローグラフ（DFG）のノード種別。 */
export type FlowKind =
  | 'param'
  | 'local'
  | 'global'
  | 'property'
  | 'call'
  | 'return'
  | 'assignment'
  | 'literal'
  | 'template'
  | 'unknown';

/** ソースファイル内の 1 点。 */
export interface Position {
  /** 1-based の行番号。 */
  readonly line: number;
  /** 1-based の列番号。 */
  readonly column: number;
}

/** ソースファイル内の範囲（両端を含む）。 */
export interface Range {
  readonly start: Position;
  readonly end: Position;
}

/** ソースファイルの絶対パスと、その読み込み時に計算したハッシュ。 */
export interface SourceFileInfo {
  /** 絶対パス（POSIX 区切りに正規化済み）。 */
  readonly path: string;
  /** プロジェクトルートからの相対パス（POSIX 区切り）。 */
  readonly relativePath: string;
  /** 内容の SHA-256（先頭 16 進 16 文字）。再現性のあるレポートに使う。 */
  readonly hash: string;
  /** 行数。 */
  readonly lineCount: number;
}

// ---------------------------------------------------------------------------
// 設定（.shirokuma.yml）
// ---------------------------------------------------------------------------

/**
 * ソース（汚染の発生源）を AST パターンで指定する。
 *
 * 注意: `as const` を付けずに書けるよう、配列は可変長で受ける。
 * 明示的に固定したい場合は `satisfies readonly SourceSpec[]` を使う。
 */
export interface SourceSpec {
  readonly id: string;
  /** このソースが生成する汚染タグ。例: `['sql', 'html', 'command']`。 */
  readonly kinds: readonly string[];
  /** `require('express').query` のようなドット区切りのメンバ式。 */
  readonly member?: string;
  /** `req` のような単純識別子（引数名に一致）。 */
  readonly identifier?: string;
  /** 関数呼び出しの名前。例: `getParameter`。 */
  readonly call?: string;
  /** このソースが現れてよい関数名の許可リスト（省略時は全域）。 */
  readonly withinFunctions?: readonly string[];
  /** 人が読む説明（日本語）。 */
  readonly description?: string;
}

/** サニタイザ（汚染を無害化する関数）を指定する。 */
export interface SanitizerSpec {
  readonly id: string;
  /** 完全修飾名。例: `db.query`（プレースホルダ化された呼び出し）。 */
  readonly member?: string;
  readonly identifier?: string;
  readonly call?: string;
  /** 無害化できるタグ。空配列なら「すべて」。 */
  readonly kinds: readonly string[];
  /**
   * このサニタイザが正しく使われているかを追加検証する。
   * 例: `kind: static-sql` は第 1 引数が文字列リテラルのときだけ有効。
   */
  readonly validation?: 'static-sql' | 'constant-argument' | 'none';
  readonly description?: string;
}

/** シンク（汚染が危険になる箇所）を指定する。 */
export interface SinkSpec {
  readonly id: string;
  /** 完全修飾名。例: `child_process.exec`。 */
  readonly member?: string;
  readonly identifier?: string;
  readonly call?: string;
  /** 報告するタグ。例: `['sql']`。 */
  readonly kinds: readonly string[];
  readonly severity: Severity;
  /** 汚染が到達してよい引数の位置（0-based）。省略時は全引数。 */
  readonly taintedArgs?: readonly number[];
  /** SARIF の ruleId とドキュメントに使う短い脆弱性名。 */
  readonly cwe?: readonly string[];
  readonly message: string;
  /** 検証用の注意書き（日本語）。 */
  readonly advice?: string;
}

/** AST パターンでノードを指す汎用マッチャ。 */
export interface PatternSpec {
  readonly member?: string;
  readonly identifier?: string;
  readonly call?: string;
  /** メソッド名が動的なプロパティアクセス（例: `req[userKey]`）を許可する。 */
  readonly allowDynamic?: boolean;
}

export interface RuleSetConfig {
  readonly sources: readonly SourceSpec[];
  readonly sanitizers: readonly SanitizerSpec[];
  readonly sinks: readonly SinkSpec[];
  /** 追加の汚染伝播規則。組み込み規則に追記される。 */
  readonly propagators?: readonly PatternSpec[];
  /** 検出対象から除外するパス glob。 */
  readonly ignorePaths?: readonly string[];
}

export interface AnalysisConfig {
  /** コンテキスト感度の上限（呼び出し文脈を何段まで区別するか）。 */
  readonly maxCallDepth: number;
  /** 1 関数あたりの反復上限。暴走を防ぐ。 */
  readonly maxIterations: number;
  /** 報告するタグの許可リスト。省略時はすべて。 */
  readonly kinds?: readonly string[];
  /** 同一シンク・同一経路の重複検出を抑制する。 */
  readonly dedupe?: boolean;
}

export interface OutputConfig {
  readonly format: 'pretty' | 'json' | 'sarif' | 'markdown';
  readonly output?: string;
  /** 指定した重要度以上で非ゼロ終了する（CI ゲート）。 */
  readonly failOn?: Severity | 'none';
}

/** 完全に解決された設定。CLI と API はこの型だけを扱う。 */
export interface TaintConfig {
  readonly schemaVersion: 1;
  readonly rules: ResolvedRuleSet;
  readonly analysis: AnalysisConfig;
  readonly output: OutputConfig;
  /** 設定がどのファイルから来たか（既定は組み込み）。 */
  readonly origin: string;
}

/** 索引を張り終えたルールセット。解析ホットパスはここだけを参照する。 */
export interface ResolvedRuleSet {
  readonly sources: readonly SourceSpec[];
  readonly sanitizers: readonly SanitizerSpec[];
  readonly sinks: readonly SinkSpec[];
  readonly propagators: readonly PatternSpec[];
  readonly ignorePaths: readonly string[];
  /** `id → SinkSpec` の索引。 */
  readonly sinkById: ReadonlyMap<string, SinkSpec>;
  readonly sourceById: ReadonlyMap<string, SourceSpec>;
  readonly sanitizerById: ReadonlyMap<string, SanitizerSpec>;
}

// ---------------------------------------------------------------------------
// 中間表現（IR）
// ---------------------------------------------------------------------------

/** プロジェクト内の 1 関数（メソッド・アロー関数・関数式を含む）。 */
export interface FunctionIR {
  /** `file.ts::Class.method` 形式の安定 ID。 */
  readonly id: string;
  readonly name: string;
  /** 所属クラス名（あれば）。 */
  readonly className?: string;
  /** 所属するファイルの絶対パス。 */
  readonly file: string;
  /** 宣言の範囲（レポートの主位置）。 */
  readonly range: Range;
  /** 仮引数名（分割代入は展開した名前、順序はソース順）。 */
  readonly params: readonly ParamIR[];
  /** 関数本体の範囲。 */
  readonly bodyRange: Range;
  /** 再帰・相互再帰の検出に使う、直接呼び出している関数 ID。 */
  readonly callees: readonly string[];
  /** 解析対象外（例: 型定義のみ）かどうか。 */
  readonly analysable: boolean;
  /**
   * モジュール直下のコードを表す疑似関数かどうか（ID は `<module>`）。
   * トップレベルの初期化コードを解析するために作られる。
   */
  readonly isModuleScope?: boolean;
}

export interface ParamIR {
  readonly name: string;
  /** 0-based の位置。 */
  readonly index: number;
  /** 既定値を持つか（省略可能引数）。 */
  readonly optional: boolean;
  /** 残余引数（`...args`）か。 */
  readonly rest: boolean;
  /** 分割代入の場合はプロパティ名。 */
  readonly destructured?: readonly string[];
}

/** DFG の 1 ノード。ソースコード上の 1 つの値の発生点に対応する。 */
export interface FlowNode {
  /** `fnId#index` 形式の安定 ID。 */
  readonly id: string;
  readonly kind: FlowKind;
  readonly functionId: string;
  readonly range: Range;
  /** 人が読める短いラベル（例: `req.query.id`, `sql + name`）。 */
  readonly label: string;
  /** 呼び出しノードの場合の解決済み呼び出し先（不明なら空）。 */
  readonly resolvedCallees?: readonly string[];
  /** このノードが属する式のソーステキスト（切り詰め済み）。 */
  readonly text?: string;
  /**
   * コールバック引数の配線に使う親式ノード。
   * 例: `arr.map(x => sink(x))` の `x => sink(x)` ノードは呼び出し `arr.map(...)` を親に持つ。
   * 解析エンジンはこれを見て「呼び出しの第 i 引数 → コールバックの第 i 仮引数」を結ぶ。
   */
  readonly parentExpression?: string;
}

/** DFG の 1 辺。`from` の値が `to` へ流れ込む。 */
export interface FlowEdge {
  readonly from: string;
  readonly to: string;
  /** 伝播の種類。`summary` は関数サマリ経由（引数 → 戻り値）。 */
  readonly kind: 'assign' | 'argument' | 'return' | 'property' | 'summary';
  /** 引数位置（`kind === 'argument'` のとき）。 */
  readonly argIndex?: number;
}

/** 呼び出しサイト 1 件。`calleeIds` が複数なら、そのすべてへ流す（保守的）。 */
export interface CallSite {
  readonly nodeId: string;
  readonly callerId: string;
  /** 解決できた呼び出し先の関数 ID。未解決なら空配列。 */
  readonly calleeIds: readonly string[];
  /** 呼び出し式のソーステキスト（未解決時の診断用）。 */
  readonly text: string;
  readonly range: Range;
}

/** プロジェクト全体のデータフローグラフ。解析エンジンの入力。 */
export interface IRGraph {
  readonly functions: readonly FunctionIR[];
  readonly nodes: readonly FlowNode[];
  readonly edges: readonly FlowEdge[];
  readonly callSites: readonly CallSite[];
  /** ファイルごとの関数 ID。 */
  readonly functionsByFile: ReadonlyMap<string, readonly string[]>;
  /** ノード ID → ノード。ホットパスで引く。 */
  readonly nodeById: ReadonlyMap<string, FlowNode>;
  /** 関数 ID → 関数。 */
  readonly functionById: ReadonlyMap<string, FunctionIR>;
}

/** 「このノードは設定上のソースである」という確定情報。 */
export interface SourceOccurrence {
  readonly nodeId: string;
  readonly sourceId: string;
  readonly kinds: readonly string[];
  readonly functionId: string;
  readonly range: Range;
  readonly label: string;
}

/** 「このノードはサニタイザを通っている」という確定情報。 */
export interface SanitizerOccurrence {
  readonly nodeId: string;
  readonly sanitizerId: string;
  readonly kinds: readonly string[];
  /** 用法が正しいか（`validation` の結果）。false なら無害化されない。 */
  readonly valid: boolean;
  /** 不正と判定した理由（日本語）。 */
  readonly invalidReason?: string;
  readonly functionId: string;
  readonly range: Range;
}

/** 「このノードはシンクである」という確定情報。 */
export interface SinkOccurrence {
  readonly nodeId: string;
  readonly sinkId: string;
  readonly kinds: readonly string[];
  readonly severity: Severity;
  readonly message: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly functionId: string;
  readonly range: Range;
  readonly label: string;
  /** 汚染が到達してよい引数位置。 */
  readonly taintedArgs: readonly number[];
}

/** 汚染トークン。ソースからシンクまでの 1 本の到達経路。 */
export interface TaintToken {
  /** 発生源となったソース定義の ID。 */
  readonly sourceId: string;
  /** タグ（`sql` / `html` / `command` / `path` など）。 */
  readonly kinds: readonly string[];
  /** 現在位置のノード ID。 */
  readonly nodeId: string;
  /**
   * ここまでの経路。`proof` の組み立てに使うため、
   * 各ステップのノード ID と、サニタイズされた時点の印を持つ。
   */
  readonly path: readonly string[];
  /** 経由したサニタイザ（無害化されたタグの記録）。 */
  readonly sanitized: readonly SanitizerUse[];
}

export interface SanitizerUse {
  readonly sanitizerId: string;
  readonly kinds: readonly string[];
  readonly nodeId: string;
}

/** 関数 1 つ分の解析結果（サマリ）。呼び出し元の解析で再利用する。 */
export interface FunctionSummary {
  readonly functionId: string;
  /** 汚染された引数位置 → 汚染されて戻るか。 */
  readonly taintedReturnFromParams: readonly number[];
  /** この関数が呼ばれたとき、引数位置 i がシンク位置 j に到達するか。 */
  readonly paramToSink: readonly ParamSinkFlow[];
  /** 関数内で確定した検出（引数由来でないものを含む）。 */
  readonly findings: readonly Finding[];
  /** サマリが不動点に達したか（打ち切られた場合は false）。 */
  readonly converged: boolean;
}

export interface ParamSinkFlow {
  readonly paramIndex: number;
  readonly sinkId: string;
  /** シンク引数の位置。 */
  readonly sinkArgIndex: number;
  readonly range: Range;
}

// ---------------------------------------------------------------------------
// 検出結果
// ---------------------------------------------------------------------------

/** 実行経路の 1 ステップ（レポートで「なぜ」を説明する単位）。 */
export interface ProofStep {
  readonly nodeId: string;
  readonly file: string;
  readonly range: Range;
  readonly label: string;
  /** このステップの役割。 */
  readonly role: 'source' | 'propagate' | 'sanitize' | 'sink';
  /** 補足（例: どのサニタイザを通ったか）。 */
  readonly note?: string;
}

export interface Finding {
  /** `<ruleId>:<relativePath>:<line>:<column>` の安定 ID。 */
  readonly id: string;
  /** シンク定義の ID（`sql-injection` など）。SARIF ruleId に対応。 */
  readonly ruleId: string;
  readonly severity: Severity;
  readonly message: string;
  readonly advice?: string;
  readonly cwe?: readonly string[];
  readonly kinds: readonly string[];
  readonly sourceId: string;
  readonly sinkId: string;
  readonly file: string;
  readonly relativePath: string;
  /** シンクの位置。エディタが開くべき場所。 */
  readonly range: Range;
  readonly functionId: string;
  /** ソースからシンクまでの完全な経路。 */
  readonly proof: readonly ProofStep[];
}

// ---------------------------------------------------------------------------
// 解析結果とレポート
// ---------------------------------------------------------------------------

export interface AnalysisStats {
  readonly filesScanned: number;
  readonly functionsAnalysed: number;
  readonly flowNodes: number;
  readonly flowEdges: number;
  readonly iterations: number;
  /** 解析を打ち切った関数の ID（反復上限など）。 */
  readonly truncated: readonly string[];
  /** 解析にかかった時間（ミリ秒）。レポートの性能表示に使う。 */
  readonly elapsedMs?: number;
}

export interface AnalysisResult {
  readonly schemaVersion: 1;
  readonly tool: ToolInfo;
  readonly files: readonly SourceFileInfo[];
  readonly findings: readonly Finding[];
  readonly stats: AnalysisStats;
  /** 解析中に発生した回復可能な問題。 */
  readonly diagnostics: readonly Diagnostic[];
}

export interface ToolInfo {
  readonly name: string;
  readonly version: string;
  /** 解析エンジンのバージョン。検出結果の互換性判定に使う。 */
  readonly engineVersion: string;
  readonly configOrigin: string;
}

export interface Diagnostic {
  readonly level: 'info' | 'warning' | 'error';
  readonly message: string;
  readonly file?: string;
  readonly range?: Range;
}

/** レポータはこのインタフェースだけを実装する。 */
export interface Reporter {
  readonly format: OutputConfig['format'];
  /** 解析結果を文字列へ変換する。 */
  render(result: AnalysisResult): string;
}

export interface ScanOptions {
  /** 解析対象のルートディレクトリ。 */
  readonly root: string;
  /** 設定。省略時は組み込み既定を使う。 */
  readonly config?: TaintConfig;
  /** 追加のインクルード glob。 */
  readonly include?: readonly string[];
  readonly exclude?: readonly string[];
  /** 進捗コールバック（CLI がスピナーを出すため）。 */
  readonly onProgress?: (event: ProgressEvent) => void;
}

export interface ProgressEvent {
  readonly phase: 'discover' | 'parse' | 'ir' | 'rules' | 'solve' | 'report';
  readonly current: number;
  readonly total: number;
  readonly detail?: string;
}

/**
 * 解析エンジンだけが知る補助情報。
 *
 * `IRGraph` は整形式のグラフなので、コールバック配線のように
 * 「グラフの外側の意味づけ」はここで渡す。型を分けることで
 * IR 構築と解析エンジンを独立にテストできる。
 */
export interface AnalysisHints {
  /**
   * `arr.map(x => sink(x))` のような高階関数で、
   * 「呼び出しの第 i 引数 → コールバックの第 i 仮引数」を結ぶ配線。
   */
  readonly callbackLinks: ReadonlyMap<
    string,
    readonly {
      readonly callNodeId: string;
      readonly pairs: readonly { readonly argNodeId: string; readonly paramNodeId: string }[];
      readonly returnNodeId?: string;
    }[]
  >;
  /** 解決できなかった呼び出し名。サニタイザ判定に使う。 */
  readonly unresolvedCallees: readonly string[];
}
