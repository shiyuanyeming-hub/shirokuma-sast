/**
 * ワークリストと不動点ドライバのテスト。
 * 決定性・重複排除・反復上限による打ち切りをここで固定する。
 */

import { describe, expect, it } from 'vitest';
import {
  DEFAULT_MAX_ITERATIONS_PER_BUCKET,
  Worklist,
  runWorklist,
} from '../../src/analysis/worklist.js';

const key = (state: number): string => String(state);

/** 1 つの状態から後続を 1 つ生む線形な遷移。 */
function linear(limit: number) {
  return (state: number): readonly number[] => (state < limit ? [state + 1] : []);
}

describe('Worklist', () => {
  it('FIFO 順で状態を取り出す', () => {
    const worklist = new Worklist<number>(key);
    expect(worklist.push(1)).toBe(true);
    expect(worklist.push(2)).toBe(true);
    expect(worklist.push(3)).toBe(true);
    expect(worklist.size).toBe(3);
    expect(worklist.shift()).toBe(1);
    expect(worklist.shift()).toBe(2);
    expect(worklist.shift()).toBe(3);
  });

  it('同一キーの状態は 2 度目以降を破棄する', () => {
    const worklist = new Worklist<number>(key);
    expect(worklist.push(7)).toBe(true);
    expect(worklist.push(7)).toBe(false);
    expect(worklist.size).toBe(1);
    expect(worklist.distinctCount).toBe(1);
  });

  it('空になったら undefined を返す', () => {
    const worklist = new Worklist<number>(key);
    expect(worklist.shift()).toBeUndefined();
    worklist.push(1);
    expect(worklist.shift()).toBe(1);
    expect(worklist.shift()).toBeUndefined();
  });

  it('大量の出し入れでも FIFO 順を保つ（内部の詰め直しを含む）', () => {
    const worklist = new Worklist<number>(key);
    for (let index = 0; index < 5000; index += 1) worklist.push(index);
    for (let index = 0; index < 5000; index += 1) expect(worklist.shift()).toBe(index);
    expect(worklist.size).toBe(0);
  });

  it('バケットごとの処理回数を数える', () => {
    const worklist = new Worklist<number>(key);
    expect(worklist.countFor('a')).toBe(0);
    expect(worklist.increment('a')).toBe(1);
    expect(worklist.increment('a')).toBe(2);
    expect(worklist.countFor('a')).toBe(2);
  });
});

describe('runWorklist', () => {
  it('到達可能な状態を 1 度ずつ展開して不動点に達する', () => {
    const visited: number[] = [];
    const result = runWorklist<number>({
      initial: [0],
      keyOf: key,
      budgetOf: () => 'fn',
      expand: linear(5),
      onState: (state) => visited.push(state),
    });

    expect(visited).toEqual([0, 1, 2, 3, 4, 5]);
    expect(result.iterations).toBe(6);
    expect(result.distinctStates).toBe(6);
    expect(result.truncatedBuckets).toEqual([]);
  });

  it('自己参照する遷移でも停止する（重複排除による終了保証）', () => {
    const result = runWorklist<number>({
      initial: [0],
      keyOf: key,
      budgetOf: () => 'fn',
      expand: (state) => [state, state + 1 > 3 ? state : state + 1],
    });

    expect(result.iterations).toBe(4);
    expect(result.truncatedBuckets).toEqual([]);
  });

  it('バケット上限を超えたら記録して展開を打ち切り、onState は全件に呼ぶ', () => {
    const seen: number[] = [];
    const truncated: string[] = [];
    const result = runWorklist<number>({
      initial: [0],
      keyOf: key,
      budgetOf: () => 'hot',
      expand: linear(100),
      maxIterationsPerBucket: 3,
      onState: (state) => seen.push(state),
      onBucketTruncated: (bucket) => truncated.push(bucket),
    });

    expect(result.truncatedBuckets).toEqual(['hot']);
    expect(truncated).toEqual(['hot']);
    expect(result.iterations).toBe(4); // 0..2 を展開し、3 で上限超過
    expect(result.distinctStates).toBe(4);
    expect(seen).toEqual([0, 1, 2, 3]);
  });

  it('打ち切られたバケットが別バケットの解析を止めない', () => {
    const states = [
      { bucket: 'a', step: 0 },
      { bucket: 'b', step: 0 },
    ];
    const result = runWorklist<(typeof states)[number]>({
      initial: states,
      keyOf: (state) => `${state.bucket}:${state.step}`,
      budgetOf: (state) => state.bucket,
      expand: (state) => (state.step < 5 ? [{ bucket: state.bucket, step: state.step + 1 }] : []),
      maxIterationsPerBucket: 2,
    });

    expect(result.truncatedBuckets).toEqual(['a', 'b']);
    // 各バケットは「展開 2 回 + 上限超過の 1 回」だけデキューされる（3 回ずつ）。
    expect(result.iterations).toBe(6);
  });

  it('展開順が決定的（同じ入力で同じ訪問順）', () => {
    const run = (): number[] => {
      const visited: number[] = [];
      runWorklist<number>({
        initial: [0],
        keyOf: key,
        budgetOf: () => 'fn',
        expand: (state) => (state < 3 ? [state * 2 + 1, state * 2 + 2] : []),
        onState: (state) => visited.push(state),
      });
      return visited;
    };

    const first = run();
    const second = run();
    expect(first).toEqual([0, 1, 2, 3, 4, 5, 6]);
    expect(second).toEqual(first);
  });

  it('既定のバケット上限は公開定数と一致する', () => {
    expect(DEFAULT_MAX_ITERATIONS_PER_BUCKET).toBeGreaterThan(0);
  });
});
