/**
 * レポータの公開エントリポイント。
 *
 * 使い方:
 * ```ts
 * import { createReporter } from './reporters/index.js';
 * const reporter = createReporter('sarif', { informationUri: 'https://example.com/repo' });
 * process.stdout.write(reporter.render(result));
 * ```
 *
 * 注意: `./contract.js` は `declare function` だけを持つ型専用のモジュールで、
 * 実行時の値を持たない。**値を import できるのはこのファイルだけ**なので、
 * パイプライン（CLI / engine）は必ずここから読み込むこと。
 */

import type { OutputConfig, Reporter } from '../types.js';
import { createJsonReporter } from './json.js';
import { createMarkdownReporter } from './markdown.js';
import { createPrettyReporter } from './pretty.js';
import { createSarifReporter, validateSarifStructure } from './sarif.js';

export { createJsonReporter };
export { createMarkdownReporter };
export { createPrettyReporter };
export { createSarifReporter };
export { validateSarifStructure };
export type { MarkdownReporterOptions } from './markdown.js';
export type { PrettyReporterOptions } from './pretty.js';
export type { SarifReporterOptions } from './sarif.js';
export { DEFAULT_INFORMATION_URI, FINGERPRINT_KEY, SARIF_SCHEMA_URI, SARIF_VERSION } from './sarif.js';
export type { ReporterInput } from './contract.js';

/** `createReporter` が受け付ける出力形式。`OutputConfig['format']` と同一。 */
export type ReporterFormat = OutputConfig['format'];

/** `createReporter` のオプション。レポータごとに使う値が異なる。 */
export interface CreateReporterOptions {
  /** pretty レポータの ANSI 出力（既定 false）。 */
  readonly color?: boolean;
  /** SARIF の `tool.driver.informationUri`。 */
  readonly informationUri?: string;
}

/**
 * 出力形式からレポータを引く。
 *
 * @param format `pretty` / `json` / `sarif` / `markdown`。
 * @param options レポータごとのオプション。
 * @returns 指定形式のレポータ。
 * @throws 未知の形式が実行時に渡された場合（型上は網羅済み）。
 */
export function createReporter(format: ReporterFormat, options?: CreateReporterOptions): Reporter {
  switch (format) {
    case 'pretty':
      return createPrettyReporter(
        options?.color === undefined ? {} : { color: options.color },
      );
    case 'json':
      return createJsonReporter();
    case 'sarif':
      return createSarifReporter(
        options?.informationUri === undefined ? {} : { informationUri: options.informationUri },
      );
    case 'markdown':
      return createMarkdownReporter();
    default: {
      const unknown: never = format;
      throw new Error(`未知の出力形式です: ${String(unknown)}`);
    }
  }
}
