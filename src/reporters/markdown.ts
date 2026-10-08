/**
 * Markdown レポータ — PR コメント・`reports/` への保存向けの出力。
 *
 * 設計方針:
 * - 検出ラベル・メッセージ・パスはスキャン対象のソース由来、つまり信頼できない入力である。
 *   とくに `|` は Markdown のテーブルを、バッククォートはコードスパンを壊し、
 *   `<script>` は生 HTML として解釈されうる。文脈ごとに正しい方法で無害化する。
 *   - テーブルセル: インライン記法をバックスラッシュでエスケープした「素のテキスト」を置く。
 *     セル内では HTML エンティティ化と `|` のエスケープを必ず行う。
 *   - コードスパン（テーブル外）: CommonMark の規則どおり、内容に含まれる最長の
 *     バッククォート連より 1 文字長いフェンスを使う。端がバッククォートの場合は前後に空白を足す。
 * - 改行・タブなどの制御文字は空白へ畳んでから出力する（表や見出しが複数行に割れないように）。
 * - 検出の並び順は入力のまま尊重する。正準順序を決めるのは解析エンジンの責務である。
 */

import type { AnalysisResult, Diagnostic, Finding, ProofStep, Reporter, Severity } from '../types.js';

/** `createMarkdownReporter` のオプション。 */
export interface MarkdownReporterOptions {
  /** 出力する検出の上限（既定は無制限）。超過分は件数だけを示す。 */
  readonly maxFindings?: number;
}

/** 制御文字を空白へ置換する（改行・タブ・ESC・C1 すべて）。 */
function stripControls(text: string): string {
  let out = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    if (code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f)) {
      out += ' ';
      continue;
    }
    out += char;
  }
  return out;
}

/**
 * 前後の空白と連続する空白（改行を含む）を 1 つへ畳む。
 *
 * @param text 対象文字列。
 * @returns 1 行相当の文字列。
 */
function collapse(text: string): string {
  return stripControls(text).replace(/\s+/gu, ' ').trim();
}

/**
 * インライン文脈（見出し・本文・テーブルセル）向けに Markdown 記法を無効化する。
 *
 * `&` `<>` をエンティティ化して生 HTML を封じ、そのほかの記法文字は
 * バックスラッシュでエスケープする。エスケープ順序は「実体参照 → バックスラッシュ →
 * その他の記法文字」で、挿入したバックスラッシュを二重に処理しない。
 *
 * @param text 信頼できない可能性のある文字列。
 * @returns そのままでは記法として解釈されない文字列。
 */
function escapeInline(text: string): string {
  return collapse(text)
    .replace(/&/gu, '&amp;')
    .replace(/</gu, '&lt;')
    .replace(/>/gu, '&gt;')
    .replace(/\\/gu, '\\\\')
    .replace(/`/gu, '\\`')
    .replace(/\|/gu, '\\|')
    .replace(/([*_[\]~])/gu, '\\$1');
}

/**
 * CommonMark のコードスパンを組み立てる。
 *
 * @param text 信頼できない可能性のある文字列。
 * @returns 内容がそのまま表示されるコードスパン。
 */
function codeSpan(text: string): string {
  const content = collapse(text);
  const runs = content.match(/`+/gu) ?? [];
  const longest = runs.reduce((max, run) => Math.max(max, run.length), 0);
  const fence = '`'.repeat(longest + 1);
  const padding = content.startsWith('`') || content.endsWith('`') ? ' ' : '';
  return `${fence}${padding}${content}${padding}${fence}`;
}

/**
 * CWE 表記から番号を取り出す。
 *
 * @param cwe `CWE-89` / `cwe-89` / `89` など。
 * @returns CWE 番号。数字が含まれない場合は null。
 */
function cweNumber(cwe: string): number | null {
  const matched = /(\d+)/u.exec(cwe);
  const digits = matched?.[1];
  if (digits === undefined) {
    return null;
  }
  const value = Number.parseInt(digits, 10);
  return Number.isFinite(value) ? value : null;
}

/**
 * CWE の表示ラベルを作る。
 *
 * @param cwe CWE 表記。
 * @returns `CWE-89` 形式、番号が取れない場合は元の文字列。
 */
function cweLabel(cwe: string): string {
  const value = cweNumber(cwe);
  return value === null ? collapse(cwe) : `CWE-${value}`;
}

/**
 * CWE の説明ページ URL を作る。
 *
 * @param cwe CWE 表記。
 * @returns MITRE の URL。番号が取れない場合は null。
 */
function cweUrl(cwe: string): string | null {
  const value = cweNumber(cwe);
  return value === null ? null : `https://cwe.mitre.org/data/definitions/${value}.html`;
}

/**
 * 検出の表示パスを組み立てる。
 *
 * @param finding 対象の検出。
 * @returns `path:line:column`。
 */
function formatLocation(finding: Finding): string {
  const path = finding.relativePath === '' ? finding.file : finding.relativePath;
  return `${path}:${finding.range.start.line}:${finding.range.start.column}`;
}

/**
 * `file`（絶対パス）と `relativePath` からプロジェクトルートを推定する。
 *
 * レポータ同士を依存させないため、この 10 行は pretty / markdown に意図的に重複させている。
 *
 * @param file 絶対パス。
 * @param relativePath ルート相対パス。
 * @returns 推定できたルート。推定できないときは null。
 */
function inferProjectRoot(file: string, relativePath: string): string | null {
  const absolute = file.replace(/\\/gu, '/');
  const relative = relativePath.replace(/\\/gu, '/').replace(/^\.\//u, '');
  if (relative === '') {
    return null;
  }
  return absolute.endsWith(`/${relative}`)
    ? absolute.slice(0, absolute.length - relative.length - 1)
    : null;
}

/**
 * 経路ステップのパスを、推定ルートからの相対パスへ短縮する。
 *
 * @param path ステップのファイルパス。
 * @param root 推定済みルート。
 * @returns 表示用パス。
 */
function shortenPath(path: string, root: string | null): string {
  const normalized = path.replace(/\\/gu, '/');
  if (root === null || root === '') {
    return normalized;
  }
  return normalized.startsWith(`${root}/`) ? normalized.slice(root.length + 1) : normalized;
}

/**
 * 重要度ごとの件数を数える。
 *
 * @param findings 検出の配列。
 * @returns 重要度 → 件数。
 */
function countSeverities(findings: readonly Finding[]): Readonly<Record<Severity, number>> {
  const counts: Record<Severity, number> = { error: 0, warning: 0, note: 0 };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

/**
 * `maxFindings` を安全な値へ正規化する。
 *
 * @param value 利用者が渡した値。
 * @returns 0 以上の整数、未指定なら Infinity（無制限）。
 */
function resolveMaxFindings(value: number | undefined): number {
  if (value === undefined || !Number.isFinite(value)) {
    return Number.POSITIVE_INFINITY;
  }
  return Math.max(0, Math.floor(value));
}

/**
 * 概要（メタ情報）の箇条書きを描画する。
 *
 * @param result 解析結果。
 * @returns 行の配列。
 */
function renderSummary(result: AnalysisResult): string[] {
  const counts = countSeverities(result.findings);
  const stats = result.stats;
  return [
    `- ツール: ${codeSpan(result.tool.name)} ${collapse(result.tool.version)}（エンジン ${collapse(result.tool.engineVersion)}）`,
    `- 設定: ${codeSpan(result.tool.configOrigin)}`,
    `- スキャン: ${stats.filesScanned} ファイル / ${stats.functionsAnalysed} 関数（iterations ${stats.iterations}、ノード ${stats.flowNodes} / エッジ ${stats.flowEdges}）`,
    `- 検出: **${result.findings.length} 件**（error ${counts.error} / warning ${counts.warning} / note ${counts.note}）`,
  ];
}

/**
 * 検出一覧のテーブルを描画する。
 *
 * @param findings 表示対象の検出。
 * @param total 全体の検出数（省略注記に使う）。
 * @returns 行の配列。
 */
function renderTable(findings: readonly Finding[], total: number): string[] {
  const lines: string[] = [
    '| # | 重要度 | ルール | 位置 | メッセージ |',
    '| ---: | :--- | :--- | :--- | :--- |',
  ];
  findings.forEach((finding, index) => {
    const message = escapeInline(finding.message);
    const cells = [
      String(index + 1),
      escapeInline(finding.severity),
      escapeInline(finding.ruleId),
      escapeInline(formatLocation(finding)),
      message === '' ? '_(メッセージなし)_' : message,
    ];
    lines.push(`| ${cells.join(' | ')} |`);
  });
  if (total > findings.length) {
    lines.push('');
    lines.push(`> 残り ${total - findings.length} 件の検出は省略しました（先頭 ${findings.length} 件のみ表示）。`);
  }
  return lines;
}

/** 検出 1 件分の詳細セクションを描画する。 */
function renderDetail(finding: Finding, index: number, root: string | null): string[] {
  const lines: string[] = [
    `### ${index + 1}. ${escapeInline(finding.severity)} — ${escapeInline(finding.ruleId)}`,
    '',
    `- 位置: ${codeSpan(formatLocation(finding))}`,
    `- 関数: ${codeSpan(finding.functionId)}`,
  ];
  if (finding.kinds.length > 0) {
    lines.push(`- タグ: ${finding.kinds.map((kind) => codeSpan(kind)).join(', ')}`);
  }
  if (finding.cwe !== undefined && finding.cwe.length > 0) {
    const links = finding.cwe.map((cwe) => {
      const url = cweUrl(cwe);
      const label = cweLabel(cwe);
      return url === null ? escapeInline(label) : `[${escapeInline(label)}](${url})`;
    });
    lines.push(`- CWE: ${links.join(', ')}`);
  }
  const message = collapse(finding.message);
  lines.push(`- メッセージ: ${message === '' ? '_(メッセージなし)_' : escapeInline(message)}`);
  if (finding.advice !== undefined && collapse(finding.advice) !== '') {
    lines.push(`- 推奨: ${escapeInline(finding.advice)}`);
  }
  lines.push('', '**汚染経路**', '');

  if (finding.proof.length === 0) {
    lines.push('_経路情報はありません。_');
    return lines;
  }
  finding.proof.forEach((step: ProofStep, stepIndex: number) => {
    const note = step.note === undefined ? '' : `（${codeSpan(step.note)}）`;
    lines.push(
      `${stepIndex + 1}. ${codeSpan(step.role)} — ${codeSpan(`${shortenPath(step.file, root)}:${step.range.start.line}:${step.range.start.column}`)} — ${codeSpan(step.label)}${note}`,
    );
  });
  return lines;
}

/**
 * 診断のセクションを描画する。
 *
 * @param diagnostics 診断の配列。
 * @returns 行の配列。
 */
function renderDiagnostics(diagnostics: readonly Diagnostic[]): string[] {
  const lines: string[] = [
    '## 診断',
    '',
    '| 重要度 | 位置 | メッセージ |',
    '| :--- | :--- | :--- |',
  ];
  for (const diagnostic of diagnostics) {
    const position =
      diagnostic.file === undefined
        ? ''
        : `${diagnostic.file}${
            diagnostic.range === undefined
              ? ''
              : `:${diagnostic.range.start.line}:${diagnostic.range.start.column}`
          }`;
    lines.push(
      `| ${escapeInline(diagnostic.level)} | ${escapeInline(position)} | ${escapeInline(diagnostic.message)} |`,
    );
  }
  return lines;
}

/**
 * 解析結果を Markdown へ変換する。
 *
 * @param result 解析結果。
 * @param maxFindings 表示する検出の上限。
 * @returns 末尾に改行を含む Markdown 文字列。
 */
function renderMarkdown(result: AnalysisResult, maxFindings: number): string {
  const lines: string[] = [`# ${escapeInline(result.tool.name)} レポート`, ''];
  lines.push(...renderSummary(result), '');

  if (result.findings.length === 0) {
    lines.push(
      `**検出なし** — ${result.stats.filesScanned} ファイル / ${result.stats.functionsAnalysed} 関数を解析しました。`,
      '',
    );
  } else {
    const shown = result.findings.slice(0, maxFindings);
    lines.push('## 検出一覧', '', ...renderTable(shown, result.findings.length), '');

    if (shown.length > 0) {
      lines.push('## 検出の詳細', '');
      shown.forEach((finding, index) => {
        const root = inferProjectRoot(finding.file, finding.relativePath);
        lines.push(...renderDetail(finding, index, root), '');
      });
    }
  }

  if (result.diagnostics.length > 0) {
    lines.push(...renderDiagnostics(result.diagnostics), '');
  }
  if (result.stats.truncated.length > 0) {
    const ids = result.stats.truncated.map((id) => codeSpan(id)).join(', ');
    lines.push(`> 解析を打ち切った関数: ${ids}`, '');
  }

  return `${lines.join('\n').trimEnd()}\n`;
}

/**
 * Markdown レポータを生成する。
 *
 * @param options `maxFindings` で一覧と詳細に載せる件数を制限する（既定は無制限）。
 * @returns `format === 'markdown'` のレポータ。
 */
export function createMarkdownReporter(options?: MarkdownReporterOptions): Reporter {
  const maxFindings = resolveMaxFindings(options?.maxFindings);
  return {
    format: 'markdown',
    render: (result) => renderMarkdown(result, maxFindings),
  };
}
