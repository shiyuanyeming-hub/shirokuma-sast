/**
 * IR 構築が外部（解析エンジン・テスト）へ渡す補助情報の型。
 *
 * 実装側は可変な配列を扱い、公開側は `readonly` で受け取る。
 * 型を分けることで、構築中の書き換えと利用側の不変性を同時に満たす。
 */

/** 「呼び出しの第 i 引数 → コールバックの第 i 仮引数」の配線情報。 */
export interface CallbackLink {
  /** 呼び出し式ノード。 */
  readonly callNodeId: string;
  /** 引数の位置と、対応するコールバック仮引数ノード。 */
  readonly pairs: readonly { readonly argNodeId: string; readonly paramNodeId: string }[];
  /** コールバック本体の return ノード（戻り値の合流に使う）。 */
  readonly returnNodeId?: string;
}

/**
 * IR だけでは決まらない、解析エンジン向けの補助情報。
 *
 * - `callbackLinks`: 高階関数（`arr.map(x => ...)` など）で、
 *   呼び出しの引数からコールバックの仮引数へ汚染を渡すための配線。
 * - `unresolvedCallees`: 解決できなかった呼び出し名。解析エンジンは
 *   これを見て「未知の関数呼び出し」の扱い（サニタイザ判定）を決める。
 */
export interface SolverHints {
  readonly callbackLinks: ReadonlyMap<string, readonly CallbackLink[]>;
  readonly unresolvedCallees: readonly string[];
}

/** 何も配線が無いときの既定値。 */
export const EMPTY_SOLVER_HINTS: SolverHints = {
  callbackLinks: new Map(),
  unresolvedCallees: [],
};
