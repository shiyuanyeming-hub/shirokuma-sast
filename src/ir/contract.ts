/**
 * IR 構築 — モジュールコントラクト
 *
 * 実装担当はこのファイルのシグネチャを変更しないこと。
 *
 * 責務: TypeScript ソース集合を、解析エンジンが消費するデータフローグラフへ変換する。
 * この段は **設定（ルール）に依存しない**。どの式がソース／サニタイザ／シンクかは
 * `src/rules/annotate.ts` が後段で判定する。
 *
 * 必須の伝播（すべて実装し、テストで固定すること）:
 *   1. 変数宣言・代入            `const x = tainted;`
 *   2. 再代入                    `x = tainted;`
 *   3. 文字列連結                `'a' + tainted + 'b'`
 *   4. テンプレートリテラル      `` `a${tainted}b` ``
 *   5. 配列・オブジェクト生成     `[tainted]`, `{ k: tainted }`
 *   6. プロパティ読み書き         `obj.k = tainted; sink(obj.k)`
 *   7. 呼び出し引数               `f(tainted)`（argIndex を記録）
 *   8. 分割代入                   `const { a } = tainted;`, `const [b] = tainted;`
 *   9. スプレッド                 `f(...tainted)`, `{ ...tainted }`
 *  10. 関数戻り値                 `return tainted;` → 呼び出し式ノードへ
 *  11. アロー式の暗黙 return       `x => x.body`（式本体）
 *  12. ローカル関数の呼び出し解決  同一ファイル内の宣言・式・`const f = () => {}`
 *  13. メソッド呼び出しの解決      `this.m(x)` / `obj.m(x)`（同名 1 件に限り解決）
 *  14. クラスメソッド・getter      `class C { m(){} get g(){} }`
 *  15. 高階関数                    `arr.map(tainted => ...)`, `forEach`, コールバック引数
 *  16. 関数引数 → 戻り値の連鎖      `function id(x){ return x; } sink(id(t))`
 *
 * 保守性の原則:
 * - 解決できない呼び出しは `calleeIds: []` とし、診断を積む（黙って落とさない）。
 * - 動的プロパティ `obj[key]` は、`key` が汚染されている場合も伝播させる。
 * - ループ・条件分岐はフロー鈍感（flow-insensitive）でよいが、
 *   同一関数内の後方定義も到達させる（不動点まで反復する前提）。
 */
import type {
  Diagnostic,
  IRGraph,
  ProgressEvent,
  SourceFileInfo,
} from '../types.js';

/** IR 構築の入力。`files` は絶対パスの一覧（順序は決定的にソート済みであること）。 */
export interface BuildIROptions {
  /** 解析対象ファイルの絶対パス。 */
  readonly files: readonly string[];
  /** プロジェクトルート。`relativePath` の算出に使う。 */
  readonly root: string;
  /** ハッシュに使う 16 進文字数（既定 16）。 */
  readonly hashLength?: number;
  /** 進捗通知。 */
  readonly onProgress?: (event: ProgressEvent) => void;
}

export interface BuildIRResult {
  readonly graph: IRGraph;
  readonly files: readonly SourceFileInfo[];
  readonly diagnostics: readonly Diagnostic[];
}

/**
 * ファイル群を解析し、データフローグラフを構築する。
 *
 * - 読み込めないファイルは `diagnostics` に `error` を積み、残りを続行する。
 * - 構文エラーを含むファイルは `warning` を積む（部分的な AST でも解析を続ける）。
 * - `graph.nodes` / `graph.edges` の順序は決定的でなければならない（テストの再現性）。
 */
export declare function buildIR(options: BuildIROptions): Promise<BuildIRResult>;

/**
 * ソーステキストを解析して IR を作る。`buildIR` が内部で使うほか、
 * テストや `<code>` 断片の解析に単体で使う。
 */
export declare function buildIRFromSource(
  source: string,
  relativePath: string,
  options?: { readonly root?: string },
): IRGraph;

/**
 * 式ノードのソーステキストをラベル用に正規化する。
 * 連続する空白・改行を 1 つに畳み、80 文字で切り詰める。
 * 例: `sql + " AND id = " + id` → そのまま 1 行へ
 */
export declare function normalizeLabel(text: string, maxLength?: number): string;

/**
 * `file.ts::Class.method` 形式の関数 ID を組み立てる。
 * 同名メソッドの衝突を避けるため、クラス名がある場合は必ず含める。
 */
export declare function makeFunctionId(relativePath: string, className: string | undefined, name: string): string;
