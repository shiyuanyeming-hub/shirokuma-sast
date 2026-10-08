/**
 * SARIF 2.1.0 レポータ — GitHub Code Scanning などで読める標準形式。
 *
 * 仕様上の要点（すべてテストで固定している）:
 * - `version` は `"2.1.0"`、`$schema` は SARIF 2.1.0 の JSON Schema を指す。
 * - `runs[0].tool.driver` に `name` / `version` / `informationUri` / `rules` を必ず入れる。
 * - `rules[]` は検出に現れた `ruleId` の重複を除いた一覧で、`id` の昇順（コード単位比較）に並べる。
 *   `results[].ruleIndex` はこの配列の添字である。
 * - `results[].level` は `error | warning | note` へ 1 対 1 で写像する。
 * - `region` は 1-based。**SARIF の `endLine` / `endColumn` は「最後の文字の次」を指す**
 *   排他的な終端なので、`types.ts` の包括的な `Range.end` に +1 して変換する。
 * - `codeFlows[0].threadFlows[0].locations` に汚染経路を入れ、GitHub が経路を表示できるようにする。
 *   `importance` は source / sink を `essential`、それ以外を `important` とする。
 * - `partialFingerprints` に安定 ID（`<tool>/<name>` 形式のキー）を入れ、再実行時に
 *   同じ指摘として扱われるようにする。
 * - `properties["security-severity"]` は **意図的に出さない**。`Severity` は CVSS ではなく
 *   修正優先度のラベルであり、数値スコアを捏造すると誤解を招くため。
 * - 検出の並び順は入力のまま尊重する。正準順序を決めるのは解析エンジンの責務である。
 */

import type { AnalysisResult, Diagnostic, Finding, ProofStep, Range, Reporter, Severity } from '../types.js';

/** `createSarifReporter` のオプション。 */
export interface SarifReporterOptions {
  /** `tool.driver.informationUri` に出す URL。省略時は {@link DEFAULT_INFORMATION_URI}。 */
  readonly informationUri?: string;
}

/** 出力する SARIF のバージョン。 */
export const SARIF_VERSION = '2.1.0';

/** SARIF 2.1.0 の JSON Schema URL。GitHub Code Scanning のドキュメントと同じ場所を指す。 */
export const SARIF_SCHEMA_URI = 'https://json.schemastore.org/sarif-2.1.0.json';

/** `informationUri` の既定値。CLI からリポジトリ URL へ差し替えられる。 */
export const DEFAULT_INFORMATION_URI = 'https://github.com/shirokuma-sast/shirokuma-sast';

/** `partialFingerprints` のキー。SARIF 仕様が推奨する `<tool>/<name>` 形式に従う。 */
export const FINGERPRINT_KEY = 'shirokuma-sast/v1';

/** SARIF の `result.level` / `reportingDescriptor.defaultConfiguration.level`。 */
type SarifLevel = 'error' | 'warning' | 'note';

/** 経路ステップの重要度。 */
type SarifImportance = 'important' | 'essential' | 'unimportant';

/** 重要度から SARIF の level への写像。 */
const SARIF_LEVELS: Readonly<Record<Severity, SarifLevel>> = {
  error: 'error',
  warning: 'warning',
  note: 'note',
};

/** 診断の重要度から SARIF の通知 level への写像（SARIF に `info` は無いので `note` へ寄せる）。 */
const NOTIFICATION_LEVELS: Readonly<Record<Diagnostic['level'], SarifLevel>> = {
  info: 'note',
  warning: 'warning',
  error: 'error',
};

/** 経路ステップの役割から `threadFlowLocation.importance` への写像。 */
const STEP_IMPORTANCE: Readonly<Record<ProofStep['role'], SarifImportance>> = {
  source: 'essential',
  sink: 'essential',
  sanitize: 'important',
  propagate: 'important',
};

/** パスを推定できなかったときに使う URI。 */
const UNKNOWN_URI = '(unknown)';

/** SARIF の `message`。`text` は必須で、`markdown` は補助表現。 */
interface SarifMessage {
  readonly text: string;
  readonly markdown?: string;
}

/** SARIF の `artifactLocation`。`uri` はリポジトリ相対の URI 参照。 */
interface SarifArtifactLocation {
  readonly uri: string;
}

/** SARIF の `region`。行・列は 1-based、`endLine` / `endColumn` は排他的な終端。 */
interface SarifRegion {
  readonly startLine: number;
  readonly startColumn: number;
  readonly endLine: number;
  readonly endColumn: number;
}

/** SARIF の `physicalLocation`。 */
interface SarifPhysicalLocation {
  readonly artifactLocation: SarifArtifactLocation;
  /** 範囲が分かっているときだけ入る（診断のように位置を持たない場合がある）。 */
  readonly region?: SarifRegion;
}

/** SARIF の `location`。 */
interface SarifLocation {
  readonly physicalLocation: SarifPhysicalLocation;
  readonly message?: SarifMessage;
}

/** SARIF の `threadFlowLocation`（経路の 1 ステップ）。 */
interface SarifThreadFlowLocation {
  readonly location: SarifLocation;
  readonly executionOrder: number;
  readonly importance: SarifImportance;
}

/** SARIF の `threadFlow`。`locations` は minItems: 1。 */
interface SarifThreadFlow {
  readonly locations: readonly SarifThreadFlowLocation[];
}

/** SARIF の `codeFlow`。`threadFlows` は minItems: 1。 */
interface SarifCodeFlow {
  readonly threadFlows: readonly SarifThreadFlow[];
}

/** SARIF の `reportingDescriptor`（`driver.rules` の要素）。 */
interface SarifReportingDescriptor {
  readonly id: string;
  readonly name: string;
  readonly shortDescription: SarifMessage;
  readonly fullDescription: SarifMessage;
  readonly help: SarifMessage;
  readonly helpUri: string;
  readonly defaultConfiguration: { readonly level: SarifLevel };
  readonly properties: { readonly tags: readonly string[] };
}

/** SARIF の `result`（検出 1 件）。 */
interface SarifResult {
  readonly ruleId: string;
  readonly ruleIndex: number;
  readonly level: SarifLevel;
  readonly message: SarifMessage;
  readonly locations: readonly SarifLocation[];
  readonly codeFlows?: readonly SarifCodeFlow[];
  readonly partialFingerprints: Readonly<Record<string, string>>;
  readonly properties: {
    readonly kinds: readonly string[];
    readonly sourceId: string;
    readonly sinkId: string;
    readonly functionId: string;
    readonly cwe?: readonly string[];
  };
}

/** SARIF の `notification`（回復可能な問題の通知）。 */
interface SarifNotification {
  readonly level: SarifLevel;
  readonly message: SarifMessage;
  readonly locations?: readonly SarifLocation[];
}

/** SARIF の `invocation`。 */
interface SarifInvocation {
  readonly executionSuccessful: boolean;
  readonly toolExecutionNotifications?: readonly SarifNotification[];
}

/** SARIF の `toolComponent`（ここでは driver のみ使う）。 */
interface SarifDriver {
  readonly name: string;
  readonly version: string;
  readonly informationUri: string;
  readonly rules: readonly SarifReportingDescriptor[];
}

/** SARIF の `run`。 */
interface SarifRun {
  readonly tool: { readonly driver: SarifDriver };
  readonly columnKind: 'utf16CodeUnits';
  readonly invocations: readonly SarifInvocation[];
  readonly results: readonly SarifResult[];
}

/** SARIF ログのルート。 */
interface SarifLog {
  readonly $schema: string;
  readonly version: string;
  readonly runs: readonly SarifRun[];
}

/**
 * 制御文字を空白へ畳んで 1 行にする（SARIF のメッセージ表示を崩さないため）。
 *
 * @param text 対象文字列。
 * @returns 1 行相当の文字列。
 */
function oneLine(text: string): string {
  let out = '';
  for (const char of text) {
    const code = char.codePointAt(0) ?? 0;
    out += code < 0x20 || code === 0x7f || (code >= 0x80 && code <= 0x9f) ? ' ' : char;
  }
  return out.replace(/\s+/gu, ' ').trim();
}

/**
 * 1 以上の整数へ正規化する。SARIF の行・列は 1 始まりが必須のため、
 * 0 や負数、非整数、NaN はすべて 1 へ丸める。
 *
 * @param value 元の値。
 * @returns 1 以上の整数。
 */
function clampPositive(value: number): number {
  if (!Number.isFinite(value)) {
    return 1;
  }
  const truncated = Math.trunc(value);
  return truncated < 1 ? 1 : truncated;
}

/**
 * `types.ts` の包括的な範囲を SARIF の region へ変換する。
 *
 * SARIF の `endLine` / `endColumn` は「最後の文字の次」を指す排他的な終端なので、
 * `Range.end` の列に +1 する。逆向きの範囲（end が start より前）は
 * 1 文字分の範囲へ正規化して、スキーマ違反の region を出さないようにする。
 *
 * @param range 1-based のソース範囲（両端を含む）。
 * @returns SARIF の region。
 */
function toRegion(range: Range): SarifRegion {
  const startLine = clampPositive(range.start.line);
  const startColumn = clampPositive(range.start.column);
  let endLine = clampPositive(range.end.line);
  let endColumn = clampPositive(range.end.column) + 1;
  if (endLine < startLine) {
    endLine = startLine;
    endColumn = startColumn + 1;
  } else if (endLine === startLine && endColumn < startColumn) {
    endColumn = startColumn + 1;
  }
  return { startLine, startColumn, endLine, endColumn };
}

/**
 * パスを URI 参照へ変換する。区切りは `/` に統一し、各セグメントをパーセント符号化する。
 *
 * @param path ファイルパス（絶対・相対のどちらでもよい）。
 * @returns URI 参照。空文字なら空文字。
 */
function toArtifactUri(path: string): string {
  const normalized = path.replace(/\\/gu, '/').replace(/^\.\//u, '');
  if (normalized === '') {
    return '';
  }
  return normalized
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
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
 * 経路ステップのパスをルート相対へ短縮する。
 *
 * @param path ステップのファイルパス。
 * @param root 推定済みルート。
 * @returns 短縮後のパス（短縮できないときは元のパス）。
 */
function shortenPath(path: string, root: string | null): string {
  const normalized = path.replace(/\\/gu, '/');
  if (root === null || root === '') {
    return normalized;
  }
  return normalized.startsWith(`${root}/`) ? normalized.slice(root.length + 1) : normalized;
}

/**
 * 検出の主位置 URI を決める。
 *
 * @param finding 対象の検出。
 * @returns URI 参照。パスが空のときは {@link UNKNOWN_URI}。
 */
function primaryUri(finding: Finding): string {
  const path = finding.relativePath === '' ? finding.file : finding.relativePath;
  return toArtifactUri(path) === '' ? UNKNOWN_URI : toArtifactUri(path);
}

/**
 * 経路ステップの位置 URI を決める。
 *
 * @param step 経路ステップ。
 * @param finding 所属する検出。
 * @param root 推定済みルート。
 * @returns URI 参照。
 */
function stepUri(step: ProofStep, finding: Finding, root: string | null): string {
  const uri = toArtifactUri(shortenPath(step.file, root));
  return uri === '' ? primaryUri(finding) : uri;
}

/**
 * 経路ステップの表示メッセージを作る。
 *
 * @param step 経路ステップ。
 * @returns `role: label (note)` 形式の 1 行。
 */
function stepMessage(step: ProofStep): string {
  const label = oneLine(step.label);
  const note = step.note === undefined ? '' : ` (${oneLine(step.note)})`;
  const head = `${step.role}:${label === '' ? '' : ` ${label}`}`;
  return `${head}${note}`;
}

/**
 * 空でないメッセージを保証する（SARIF の `message.text` は空文字を許さない）。
 *
 * @param text 元のメッセージ。
 * @param fallback 空だったときの代替。
 * @returns 空でない文字列。
 */
function safeMessage(text: string, fallback: string): string {
  const trimmed = oneLine(text);
  if (trimmed !== '') {
    return text;
  }
  return fallback === '' ? 'shirokuma-sast: 詳細不明な検出' : fallback;
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
 * ルール ID を `reportingDescriptor.name` 用の識別子へ正規化する。
 *
 * 仕様上 `name` は空白を含まない名前にすべきとされているため、空白と記号を `-` へ寄せる。
 *
 * @param ruleId ルール ID。
 * @returns 正規化した名前。
 */
function toRuleName(ruleId: string): string {
  const normalized = ruleId.trim().replace(/[^A-Za-z0-9._-]+/gu, '-').replace(/^-+|-+$/gu, '');
  return normalized === '' ? 'unknown-rule' : normalized;
}

/** ルール 1 件分の集約結果。 */
interface RuleAccumulator {
  readonly id: string;
  severity: Severity;
  message: string;
  advice: string;
  readonly cwe: string[];
  readonly kinds: string[];
}

/** 重要度の強さ。同じ ruleId が複数の重要度で現れた場合は強い方を採用する。 */
const SEVERITY_RANK: Readonly<Record<Severity, number>> = { error: 2, warning: 1, note: 0 };

/**
 * 検出から `driver.rules` を作る。`ruleId` で重複を除き、`id` の昇順に並べる。
 *
 * 並び替えは `localeCompare` ではなくコード単位比較を使う。ロケール依存の比較は
 * 環境によって順序が変わり、出力の再現性を壊すため。
 *
 * @param findings 検出の配列。
 * @returns 重複を除いたルールの配列。
 */
function collectRules(findings: readonly Finding[]): readonly RuleAccumulator[] {
  const byId = new Map<string, RuleAccumulator>();
  for (const finding of findings) {
    const existing = byId.get(finding.ruleId);
    if (existing === undefined) {
      byId.set(finding.ruleId, {
        id: finding.ruleId,
        severity: finding.severity,
        message: finding.message,
        advice: finding.advice ?? '',
        cwe: [...(finding.cwe ?? [])],
        kinds: [...finding.kinds],
      });
      continue;
    }
    if (SEVERITY_RANK[finding.severity] > SEVERITY_RANK[existing.severity]) {
      existing.severity = finding.severity;
    }
    if (oneLine(existing.message) === '' && oneLine(finding.message) !== '') {
      existing.message = finding.message;
    }
    if (oneLine(existing.advice) === '' && finding.advice !== undefined) {
      existing.advice = finding.advice;
    }
    for (const cwe of finding.cwe ?? []) {
      if (!existing.cwe.includes(cwe)) {
        existing.cwe.push(cwe);
      }
    }
    for (const kind of finding.kinds) {
      if (!existing.kinds.includes(kind)) {
        existing.kinds.push(kind);
      }
    }
  }
  return [...byId.values()].sort((left, right) =>
    left.id < right.id ? -1 : left.id > right.id ? 1 : 0,
  );
}

/**
 * ルールを `reportingDescriptor` へ変換する。
 *
 * @param rule 集約済みルール。
 * @param informationUri `helpUri` を決められなかったときの代替 URL。
 * @returns SARIF の reportingDescriptor。
 */
function toRuleDescriptor(rule: RuleAccumulator, informationUri: string): SarifReportingDescriptor {
  const numbers = rule.cwe
    .map(cweNumber)
    .filter((value): value is number => value !== null)
    .filter((value, index, all) => all.indexOf(value) === index);
  const primary = numbers[0];
  const helpUri = primary === undefined ? informationUri : `https://cwe.mitre.org/data/definitions/${primary}.html`;
  const description = oneLine(rule.message) === '' ? `ルール ${rule.id} が検出されました。` : rule.message;
  const advice = oneLine(rule.advice);
  const tags = ['security', ...numbers.map((value) => `external/cwe/cwe-${String(value).padStart(3, '0')}`)].filter(
    (tag, index, all) => all.indexOf(tag) === index,
  );
  const helpText = advice === '' ? description : `${description}\n\n推奨: ${advice}`;
  const cweLinks = numbers.map((value) => `[CWE-${value}](${cweUrl(`CWE-${value}`) ?? informationUri})`).join(', ');

  return {
    id: rule.id,
    name: toRuleName(rule.id),
    shortDescription: { text: description },
    fullDescription: { text: helpText },
    help: {
      text: helpText,
      markdown: cweLinks === '' ? helpText : `${helpText}\n\n${cweLinks}`,
    },
    helpUri,
    defaultConfiguration: { level: SARIF_LEVELS[rule.severity] },
    properties: { tags },
  };
}

/**
 * 汚染経路を `codeFlows` へ変換する。
 *
 * @param finding 対象の検出。
 * @param root 推定済みルート。
 * @returns `codeFlows`。経路が空のときは空配列（呼び出し側でキーごと省略する）。
 */
function toCodeFlows(finding: Finding, root: string | null): readonly SarifCodeFlow[] {
  if (finding.proof.length === 0) {
    return [];
  }
  const locations: SarifThreadFlowLocation[] = finding.proof.map((step, index) => ({
    location: {
      physicalLocation: {
        artifactLocation: { uri: stepUri(step, finding, root) },
        region: toRegion(step.range),
      },
      message: { text: stepMessage(step) },
    },
    executionOrder: index + 1,
    importance: STEP_IMPORTANCE[step.role],
  }));
  return [{ threadFlows: [{ locations }] }];
}

/**
 * 検出 1 件を `results[]` の要素へ変換する。
 *
 * @param finding 検出。
 * @param ruleIndex `driver.rules` 内の添字。
 * @param root 推定済みルート。
 * @returns SARIF の result。
 */
function toResult(finding: Finding, ruleIndex: number, root: string | null): SarifResult {
  const codeFlows = toCodeFlows(finding, root);
  return {
    ruleId: finding.ruleId,
    ruleIndex,
    level: SARIF_LEVELS[finding.severity],
    message: { text: safeMessage(finding.message, finding.ruleId) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: primaryUri(finding) },
          region: toRegion(finding.range),
        },
      },
    ],
    ...(codeFlows.length === 0 ? {} : { codeFlows }),
    partialFingerprints: { [FINGERPRINT_KEY]: finding.id },
    properties: {
      kinds: [...finding.kinds],
      sourceId: finding.sourceId,
      sinkId: finding.sinkId,
      functionId: finding.functionId,
      ...(finding.cwe === undefined ? {} : { cwe: [...finding.cwe] }),
    },
  };
}

/**
 * 診断 1 件を `toolExecutionNotifications` の要素へ変換する。
 *
 * @param diagnostic 診断。
 * @returns SARIF の notification。
 */
function toNotification(diagnostic: Diagnostic): SarifNotification {
  const file = diagnostic.file;
  const uri = file === undefined ? '' : toArtifactUri(file);
  const physicalLocation: SarifPhysicalLocation = {
    artifactLocation: { uri },
    ...(diagnostic.range === undefined ? {} : { region: toRegion(diagnostic.range) }),
  };
  return {
    level: NOTIFICATION_LEVELS[diagnostic.level],
    message: { text: safeMessage(diagnostic.message, 'shirokuma-sast: 診断メッセージなし') },
    ...(uri === '' ? {} : { locations: [{ physicalLocation }] }),
  };
}

/**
 * 解析結果を SARIF 2.1.0 の JSON 文字列へ変換する。
 *
 * @param result 解析結果。
 * @param informationUri `tool.driver.informationUri` に出す URL。
 * @returns 2 スペースインデントの SARIF ログ（末尾改行あり）。
 */
function renderSarif(result: AnalysisResult, informationUri: string): string {
  const rules = collectRules(result.findings);
  const ruleIndexById = new Map<string, number>();
  rules.forEach((rule, index) => {
    ruleIndexById.set(rule.id, index);
  });

  const results = result.findings.map((finding) => {
    const root = inferProjectRoot(finding.file, finding.relativePath);
    return toResult(finding, ruleIndexById.get(finding.ruleId) ?? 0, root);
  });

  const notifications = result.diagnostics.map(toNotification);
  const driverName = result.tool.name.trim() === '' ? 'shirokuma-sast' : result.tool.name;
  const driverVersion =
    result.tool.version.trim() !== ''
      ? result.tool.version
      : result.tool.engineVersion.trim() !== ''
        ? result.tool.engineVersion
        : 'unknown';

  const log: SarifLog = {
    $schema: SARIF_SCHEMA_URI,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: driverName,
            version: driverVersion,
            informationUri,
            rules: rules.map((rule) => toRuleDescriptor(rule, informationUri)),
          },
        },
        columnKind: 'utf16CodeUnits',
        invocations: [
          {
            executionSuccessful: true,
            ...(notifications.length === 0 ? {} : { toolExecutionNotifications: notifications }),
          },
        ],
        results,
      },
    ],
  };

  return `${JSON.stringify(log, null, 2)}\n`;
}

/**
 * `informationUri` を解決する。
 *
 * SARIF スキーマは `informationUri` に `format: uri`（絶対 URI）を要求するため、
 * スキームを持たない値や空文字は既定値へフォールバックさせ、
 * GitHub Code Scanning が読めないログを出力しないようにする。
 *
 * @param configured 利用者が指定した値。
 * @returns 使用する絶対 URI。
 */
function resolveInformationUri(configured: string | undefined): string {
  const candidate = configured?.trim() ?? '';
  return /^[A-Za-z][A-Za-z0-9+.-]*:/u.test(candidate) ? candidate : DEFAULT_INFORMATION_URI;
}

/**
 * SARIF 2.1.0 レポータを生成する。
 *
 * @param options `informationUri` で `tool.driver.informationUri` を差し替えられる。
 * @returns `format === 'sarif'` のレポータ。
 */
export function createSarifReporter(options?: SarifReporterOptions): Reporter {
  const informationUri = resolveInformationUri(options?.informationUri);
  return {
    format: 'sarif',
    render: (result) => renderSarif(result, informationUri),
  };
}

// ---------------------------------------------------------------------------
// 構造検証（テスト補助）
// ---------------------------------------------------------------------------

/** オブジェクト（配列を除く）かどうかを判定する。 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** 配列かどうかを判定する。`Array.isArray` の `any[]` への絞り込みを避けるための独自ヘルパ。 */
function isUnknownArray(value: unknown): value is readonly unknown[] {
  return Array.isArray(value);
}

/**
 * オブジェクトから文字列フィールドを読む。
 *
 * @param record 対象オブジェクト。
 * @param key キー。
 * @returns 文字列。存在しない、または文字列でない場合は null。
 */
function readString(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === 'string' ? value : null;
}

/**
 * 必須の非空文字列フィールドを検証する。
 *
 * @param record 対象オブジェクト。
 * @param key キー。
 * @param where 問題メッセージに使う位置。
 * @param problems 問題の蓄積先。
 * @returns 値。不正な場合は null。
 */
function requireString(
  record: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): string | null {
  const value = readString(record, key);
  if (value === null || value.trim() === '') {
    problems.push(`${where}.${key} が空、または文字列ではありません`);
    return null;
  }
  return value;
}

/**
 * 1 以上の整数フィールドを検証する。
 *
 * @param record 対象オブジェクト。
 * @param key キー。
 * @param where 問題メッセージに使う位置。
 * @param problems 問題の蓄積先。
 * @returns 値。不正な場合は null。
 */
function requirePositiveInteger(
  record: Record<string, unknown>,
  key: string,
  where: string,
  problems: string[],
): number | null {
  const value = record[key];
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
    problems.push(`${where}.${key} が 1 以上の整数ではありません`);
    return null;
  }
  return value;
}

/**
 * region の構造と 1-based 制約を検証する。
 *
 * @param value 検証対象。
 * @param where 問題メッセージに使う位置。
 * @param problems 問題の蓄積先。
 */
function checkRegion(value: unknown, where: string, problems: string[]): void {
  if (!isRecord(value)) {
    problems.push(`${where} が存在しません`);
    return;
  }
  const startLine = requirePositiveInteger(value, 'startLine', where, problems);
  const startColumn = requirePositiveInteger(value, 'startColumn', where, problems);
  const endLine = requirePositiveInteger(value, 'endLine', where, problems);
  const endColumn = requirePositiveInteger(value, 'endColumn', where, problems);
  if (startLine !== null && endLine !== null && endLine < startLine) {
    problems.push(`${where}: endLine (${endLine}) が startLine (${startLine}) より小さい`);
  }
  if (startLine !== null && startColumn !== null && endLine !== null && endColumn !== null && endLine === startLine && endColumn < startColumn) {
    problems.push(`${where}: 同一行の endColumn (${endColumn}) が startColumn (${startColumn}) より小さい`);
  }
}

/**
 * location の構造を検証する。
 *
 * @param value 検証対象。
 * @param where 問題メッセージに使う位置。
 * @param problems 問題の蓄積先。
 */
function checkLocation(value: unknown, where: string, problems: string[]): void {
  if (!isRecord(value)) {
    problems.push(`${where} が存在しません`);
    return;
  }
  const physical = value['physicalLocation'];
  if (!isRecord(physical)) {
    problems.push(`${where}.physicalLocation が存在しません`);
    return;
  }
  const artifact = physical['artifactLocation'];
  if (!isRecord(artifact)) {
    problems.push(`${where}.physicalLocation.artifactLocation が存在しません`);
  } else {
    const uri = readString(artifact, 'uri');
    if (uri === null || uri === '') {
      problems.push(`${where}.physicalLocation.artifactLocation.uri が空、または文字列ではありません`);
    }
  }
  checkRegion(physical['region'], `${where}.physicalLocation.region`, problems);
}

/**
 * SARIF 出力から GitHub Code Scanning が読む最小構造を検証する。
 *
 * 例外は投げず、見つかった問題を日本語のメッセージ配列として返す。
 * 空配列なら構造は妥当。
 *
 * @param sarif SARIF の JSON 文字列。
 * @returns 問題の一覧（空なら妥当）。
 */
export function validateSarifStructure(sarif: string): readonly string[] {
  const problems: string[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(sarif);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    return [`SARIF を JSON として解釈できません: ${detail}`];
  }

  if (!isRecord(parsed)) {
    return ['SARIF のルートがオブジェクトではありません'];
  }
  if (readString(parsed, 'version') !== SARIF_VERSION) {
    problems.push(`version が "${SARIF_VERSION}" ではありません`);
  }
  const schema = readString(parsed, '$schema');
  if (schema === null || !schema.includes('sarif')) {
    problems.push('$schema が SARIF のスキーマ URL ではありません');
  }

  const runs = parsed['runs'];
  if (!isUnknownArray(runs) || runs.length === 0) {
    problems.push('runs が空、または配列ではありません');
    return problems;
  }
  const run = runs[0];
  if (!isRecord(run)) {
    problems.push('runs[0] がオブジェクトではありません');
    return problems;
  }

  const tool = run['tool'];
  const driver = isRecord(tool) ? tool['driver'] : undefined;
  let ruleIds = new Set<string>();
  if (!isRecord(driver)) {
    problems.push('runs[0].tool.driver が存在しません');
  } else {
    requireString(driver, 'name', 'runs[0].tool.driver', problems);
    requireString(driver, 'version', 'runs[0].tool.driver', problems);
    requireString(driver, 'informationUri', 'runs[0].tool.driver', problems);

    const rules = driver['rules'];
    if (!isUnknownArray(rules)) {
      problems.push('runs[0].tool.driver.rules が配列ではありません');
    } else {
      ruleIds = new Set<string>();
      rules.forEach((rule, index) => {
        const where = `runs[0].tool.driver.rules[${index}]`;
        if (!isRecord(rule)) {
          problems.push(`${where} がオブジェクトではありません`);
          return;
        }
        const id = requireString(rule, 'id', where, problems);
        if (id !== null) {
          if (ruleIds.has(id)) {
            problems.push(`${where}.id "${id}" が重複しています`);
          }
          ruleIds.add(id);
        }
        requireString(rule, 'name', where, problems);
        const shortDescription = rule['shortDescription'];
        if (!isRecord(shortDescription)) {
          problems.push(`${where}.shortDescription が存在しません`);
        } else {
          requireString(shortDescription, 'text', `${where}.shortDescription`, problems);
        }
        const configuration = rule['defaultConfiguration'];
        const level = isRecord(configuration) ? readString(configuration, 'level') : null;
        const levels: readonly string[] = ['error', 'warning', 'note'];
        if (level === null || !levels.includes(level)) {
          problems.push(`${where}.defaultConfiguration.level が error/warning/note ではありません`);
        }
        const helpUri = rule['helpUri'];
        if (helpUri !== undefined && (typeof helpUri !== 'string' || helpUri === '')) {
          problems.push(`${where}.helpUri が空、または文字列ではありません`);
        }
      });
    }
  }

  const columnKind = run['columnKind'];
  if (columnKind !== undefined && columnKind !== 'utf16CodeUnits' && columnKind !== 'unicodeCodePoints') {
    problems.push('runs[0].columnKind が utf16CodeUnits / unicodeCodePoints ではありません');
  }

  const results = run['results'];
  if (!isUnknownArray(results)) {
    problems.push('runs[0].results が配列ではありません');
    return problems;
  }
  results.forEach((result, index) => {
    const where = `runs[0].results[${index}]`;
    if (!isRecord(result)) {
      problems.push(`${where} がオブジェクトではありません`);
      return;
    }
    const ruleId = requireString(result, 'ruleId', where, problems);
    if (ruleId !== null && driver !== undefined && isRecord(driver) && !ruleIds.has(ruleId)) {
      problems.push(`${where}.ruleId "${ruleId}" が runs[0].tool.driver.rules に存在しません`);
    }

    const level = readString(result, 'level');
    const levels: readonly string[] = ['error', 'warning', 'note'];
    if (level === null || !levels.includes(level)) {
      problems.push(`${where}.level が error/warning/note ではありません`);
    }

    const message = result['message'];
    if (!isRecord(message)) {
      problems.push(`${where}.message が存在しません`);
    } else {
      requireString(message, 'text', `${where}.message`, problems);
    }

    const locations = result['locations'];
    if (!isUnknownArray(locations) || locations.length === 0) {
      problems.push(`${where}.locations が空、または配列ではありません`);
    } else {
      checkLocation(locations[0], `${where}.locations[0]`, problems);
    }

    const fingerprints = result['partialFingerprints'];
    if (!isRecord(fingerprints)) {
      problems.push(`${where}.partialFingerprints が存在しません`);
    } else {
      const values = Object.values(fingerprints);
      if (!values.some((value) => typeof value === 'string' && value !== '')) {
        problems.push(`${where}.partialFingerprints に空でない文字列がありません`);
      }
    }

    const codeFlows = result['codeFlows'];
    if (codeFlows !== undefined) {
      if (!isUnknownArray(codeFlows) || codeFlows.length === 0) {
        problems.push(`${where}.codeFlows が空、または配列ではありません`);
        return;
      }
      const flow = codeFlows[0];
      const threadFlows = isRecord(flow) ? flow['threadFlows'] : undefined;
      if (!isUnknownArray(threadFlows) || threadFlows.length === 0) {
        problems.push(`${where}.codeFlows[0].threadFlows が空、または配列ではありません`);
        return;
      }
      const thread = threadFlows[0];
      const threadLocations = isRecord(thread) ? thread['locations'] : undefined;
      if (!isUnknownArray(threadLocations) || threadLocations.length === 0) {
        problems.push(`${where}.codeFlows[0].threadFlows[0].locations が空、または配列ではありません`);
        return;
      }
      threadLocations.forEach((entry, entryIndex) => {
        const entryWhere = `${where}.codeFlows[0].threadFlows[0].locations[${entryIndex}]`;
        if (!isRecord(entry)) {
          problems.push(`${entryWhere} がオブジェクトではありません`);
          return;
        }
        checkLocation(entry['location'], `${entryWhere}.location`, problems);
      });
    }
  });

  return problems;
}
