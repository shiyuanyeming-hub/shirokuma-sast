/**
 * ソース断片をレポート用のラベルへ正規化する。
 *
 * ラベルは「どの値が危険か」を人へ伝える唯一の手掛かりなので、
 * 連続する空白・改行を畳んで 1 行に収め、長すぎる場合は切り詰める。
 * 同じ入力に対して常に同じ出力を返す。
 */
import { collapseWhitespace, truncate } from '../util/impl.js';

/** 既定の最大長。端末 1 行に収まる長さを目安にしている。 */
export const DEFAULT_LABEL_LENGTH = 80;

/** 連続する空白・改行を 1 スペースへ畳み、`maxLength` で切り詰める。 */
export function normalizeLabel(text: string, maxLength: number = DEFAULT_LABEL_LENGTH): string {
  return truncate(collapseWhitespace(text), maxLength);
}
