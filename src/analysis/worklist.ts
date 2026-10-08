/**
 * ワークリスト法の基盤 — 決定的な FIFO キューと不動点ドライバ。
 *
 * 汚染解析は「状態（ノード × トークン）の集合」に対する不動点計算として表現できる。
 * 本モジュールはその反復エンジンだけを提供し、状態の意味論
 * （伝播規則・サニタイズ・シンク判定）は `solver.ts` が与える。
 *
 * 決定性:
 * - 初期状態の順序と `expand` が返す順序がそのまま解析の決定性を決める。
 *   呼び出し側は両方を決定的（例: ノード ID 昇順）に構成すること。
 * - キューは FIFO なので、同一キーの状態は「最初に見つかった経路」で 1 度だけ
 *   展開される（幅優先 = 最短経路が採用される）。
 *
 * 終了保証:
 * - `keyOf` による重複排除で同一状態は 1 度しか投入されない。状態空間は有限
 *   （ノード数 × ソース数 × タグ部分集合 × 引数位置）なので反復は必ず停止する。
 * - さらに「バケット」（関数など）ごとの反復上限を設け、超過したバケットは
 *   展開を打ち切って `truncatedBuckets` に記録する。相互再帰であっても
 *   全体の反復回数は「バケット数 × 上限」で抑えられ、暴走しない。
 */

/** 状態を一意に識別するキーを返す関数。 */
export type StateKeyFn<S> = (state: S) => string;

/** 状態を反復予算のバケット（関数単位など）へ割り当てる関数。 */
export type BucketKeyFn<S> = (state: S) => string;

/** 状態から後続状態を列挙する関数。返した順序が解析結果の決定性を左右する。 */
export type ExpandFn<S> = (state: S) => readonly S[];

/** バケットごとの既定反復上限。 */
export const DEFAULT_MAX_ITERATIONS_PER_BUCKET = 50_000;

/** ロケール非依存の文字列比較（決定的な整列のため）。 */
function compareStrings(a: string, b: string): number {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}

/**
 * 決定的な FIFO ワークリスト。
 *
 * 同一キーの状態は 2 回目以降 `push` が `false` を返して破棄される。
 * これにより「同じ状態を何度も展開する」ことによる無限反復を防ぐ。
 */
export class Worklist<S> {
  private readonly queue: S[] = [];
  private readonly keys = new Set<string>();
  private readonly buckets = new Map<string, number>();
  private readonly keyOf: StateKeyFn<S>;
  private head = 0;

  /**
   * 状態のキー関数を受け取ってキューを作る。
   * @param keyOf 状態を一意化するキー（同じキーの状態は 1 度だけ処理される）
   */
  constructor(keyOf: StateKeyFn<S>) {
    this.keyOf = keyOf;
  }

  /**
   * 状態を末尾へ追加する。
   * @returns 新規なら `true`、既知のキーで破棄したなら `false`
   */
  push(state: S): boolean {
    const key = this.keyOf(state);
    if (this.keys.has(key)) return false;
    this.keys.add(key);
    this.queue.push(state);
    return true;
  }

  /**
   * 先頭の状態を取り出す（FIFO）。
   * @returns 空なら `undefined`
   */
  shift(): S | undefined {
    if (this.head >= this.queue.length) return undefined;
    const state = this.queue[this.head];
    this.head += 1;
    if (this.head > 1024 && this.head * 2 > this.queue.length) this.compact();
    return state;
  }

  /** 未処理の状態数。 */
  get size(): number {
    return this.queue.length - this.head;
  }

  /** 投入された異なり状態の数（重複排除後の状態空間の大きさ）。 */
  get distinctCount(): number {
    return this.keys.size;
  }

  /** バケットの処理回数を 1 増やし、増加後の値を返す。 */
  increment(bucket: string): number {
    const next = (this.buckets.get(bucket) ?? 0) + 1;
    this.buckets.set(bucket, next);
    return next;
  }

  /** バケットの処理回数。 */
  countFor(bucket: string): number {
    return this.buckets.get(bucket) ?? 0;
  }

  /** 先頭側の処理済み領域を切り落としてメモリを解放する。 */
  private compact(): void {
    this.queue.splice(0, this.head);
    this.head = 0;
  }
}

/** 不動点ドライバの設定。 */
export interface WorklistRunOptions<S> {
  /** 初期状態。順序は決定的であること。 */
  readonly initial: readonly S[];
  /** 状態のキー関数（重複排除に使う）。 */
  readonly keyOf: StateKeyFn<S>;
  /** 状態のバケット（反復予算の単位。通常は関数 ID）。 */
  readonly budgetOf: BucketKeyFn<S>;
  /** 後続状態の列挙。順序は決定的であること。 */
  readonly expand: ExpandFn<S>;
  /** 1 バケットあたりの反復上限。省略時は `DEFAULT_MAX_ITERATIONS_PER_BUCKET`。 */
  readonly maxIterationsPerBucket?: number;
  /**
   * デキュー直後に必ず呼ばれるフック。
   * 予算超過で展開を打ち切った状態でも呼ばれるため、検出の記録に使える。
   */
  readonly onState?: (state: S) => void;
  /** バケットが上限に達して打ち切られたときに 1 度だけ呼ばれる。 */
  readonly onBucketTruncated?: (bucket: string) => void;
}

/** 不動点ドライバの結果。 */
export interface WorklistRunResult {
  /** デキューした作業項目の総数（打ち切りで展開しなかったものも含む）。 */
  readonly iterations: number;
  /** 重複排除後に展開した異なり状態の数。 */
  readonly distinctStates: number;
  /** 反復上限に達して打ち切ったバケット（昇順）。 */
  readonly truncatedBuckets: readonly string[];
}

/**
 * ワークリストが空になるまで状態を展開する不動点ドライバ。
 *
 * 打ち切りは「後続を展開しない」だけで、他のバケットの解析は継続する。
 * これにより相互再帰を含むグラフでも停止しつつ、部分的な結果を返せる。
 */
export function runWorklist<S>(options: WorklistRunOptions<S>): WorklistRunResult {
  const maxIterations = options.maxIterationsPerBucket ?? DEFAULT_MAX_ITERATIONS_PER_BUCKET;
  const worklist = new Worklist<S>(options.keyOf);
  for (const state of options.initial) worklist.push(state);

  const truncated = new Set<string>();
  let iterations = 0;

  for (;;) {
    const state = worklist.shift();
    if (state === undefined) break;
    iterations += 1;
    if (options.onState !== undefined) options.onState(state);

    const bucket = options.budgetOf(state);
    if (worklist.increment(bucket) > maxIterations) {
      if (!truncated.has(bucket)) {
        truncated.add(bucket);
        if (options.onBucketTruncated !== undefined) options.onBucketTruncated(bucket);
      }
      continue;
    }

    for (const next of options.expand(state)) worklist.push(next);
  }

  return {
    iterations,
    distinctStates: worklist.distinctCount,
    truncatedBuckets: [...truncated].sort(compareStrings),
  };
}
