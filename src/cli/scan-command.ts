/**
 * `shirokuma` CLI の実装。
 *
 * 引数解析（`args.ts`）と実際の処理を分けているので、
 * ここは「コマンドを実行して終了コードを返す」だけを担当する。
 */
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ENGINE_VERSION, TOOL_VERSION, scan, shouldFail, summarize } from '../engine.js';
import { createReporter } from '../reporters/index.js';
import type { Severity, TaintConfig } from '../types.js';
import { USAGE, CliError, parseArgs, type CliCommand } from './args.js';

export interface CliIo {
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

/** CLI の実行結果。プロセスの終了コードになる。 */
/** SARIF の `tool.driver.informationUri` に埋め込むリポジトリ URL。 */
export const REPOSITORY_URL = 'https://github.com/shiyuanyeming-hub/shirokuma-sast';

export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

/** CLI 本体。`main.ts` はこれを呼ぶだけにする（テストしやすさのため）。 */
export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  let command: CliCommand;
  try {
    command = parseArgs(argv);
  } catch (error) {
    if (error instanceof CliError) {
      io.stderr(`エラー: ${error.message}\n`);
      if (error.hint !== undefined) {
        io.stderr(`ヒント: ${error.hint}\n`);
      }
      io.stderr(`\n${USAGE}`);
      return EXIT_ERROR;
    }
    throw error;
  }

  switch (command.kind) {
    case 'help':
      io.stdout(USAGE);
      return EXIT_OK;
    case 'version':
      io.stdout(`${TOOL_VERSION} (engine ${ENGINE_VERSION}, node ${process.version})\n`);
      return EXIT_OK;
    case 'rules':
      return runRules(io, command.json);
    case 'explain':
      return runExplain(io, command.file, command.line, command.json);
    case 'scan':
      return runScan(io, command);
  }
}

/** `rules` コマンド: 組み込みルールの一覧を表示する。 */
async function runRules(io: CliIo, json: boolean): Promise<number> {
  try {
    const builtin = await loadBuiltin();
    const collection = {
      sources: builtin.BUILTIN_SOURCES.map((source) => ({
        id: source.id,
        kinds: source.kinds,
        pattern: source.member ?? source.call ?? source.identifier ?? '?',
        description: source.description ?? '',
      })),
      sanitizers: builtin.BUILTIN_SANITIZERS.map((sanitizer) => ({
        id: sanitizer.id,
        kinds: sanitizer.kinds,
        pattern: sanitizer.member ?? sanitizer.call ?? sanitizer.identifier ?? '?',
        validation: sanitizer.validation ?? 'none',
        description: sanitizer.description ?? '',
      })),
      sinks: builtin.BUILTIN_SINKS.map((sink) => ({
        id: sink.id,
        kinds: sink.kinds,
        severity: sink.severity,
        pattern: sink.member ?? sink.call ?? sink.identifier ?? '?',
        cwe: sink.cwe ?? [],
        message: sink.message,
      })),
    };

    if (json) {
      io.stdout(`${JSON.stringify(collection, null, 2)}\n`);
      return EXIT_OK;
    }

    io.stdout(`組み込みルール（ソース ${collection.sources.length} / サニタイザ ${collection.sanitizers.length} / シンク ${collection.sinks.length}）\n`);

    io.stdout('\n■ ソース（汚染の入口）\n');
    for (const source of collection.sources) {
      io.stdout(`  ${source.id.padEnd(28)} ${source.pattern.padEnd(30)} [${source.kinds.join(', ')}]\n`);
    }

    io.stdout('\n■ サニタイザ（無害化）\n');
    for (const sanitizer of collection.sanitizers) {
      const validation = sanitizer.validation === 'none' ? '' : ` 検証: ${sanitizer.validation}`;
      io.stdout(`  ${sanitizer.id.padEnd(28)} ${sanitizer.pattern.padEnd(30)} [${sanitizer.kinds.join(', ')}]${validation}\n`);
    }

    io.stdout('\n■ シンク（危険な操作）\n');
    for (const sink of collection.sinks) {
      const cwe = sink.cwe.length > 0 ? ` ${sink.cwe.join(' ')}` : '';
      io.stdout(`  ${sink.id.padEnd(28)} ${sink.pattern.padEnd(30)} ${sink.severity.padEnd(8)}${cwe}\n`);
    }
    return EXIT_OK;
  } catch (error) {
    io.stderr(`エラー: 組み込みルールを読み込めませんでした: ${describe(error)}\n`);
    return EXIT_ERROR;
  }
}

/** `explain` コマンド: 指定位置のソース・サニタイザ・シンク判定を表示する。 */
async function runExplain(io: CliIo, file: string, line: number, json: boolean): Promise<number> {
  try {
    const builtin = await loadBuiltin();
    const { buildIR } = await import('../ir/builder.js');
    const { annotate } = await import('../rules/annotate.js');
    const { resolveRuleSet } = await import('../config/loader.js');

    const root = process.cwd();
    const absolute = path.resolve(root, file);
    const built = await buildIR({ files: [absolute], root });
    const rules = resolveRuleSet({
      sources: builtin.BUILTIN_SOURCES,
      sanitizers: builtin.BUILTIN_SANITIZERS,
      sinks: builtin.BUILTIN_SINKS,
      propagators: builtin.BUILTIN_PROPAGATORS,
      ignorePaths: builtin.DEFAULT_IGNORE_PATHS,
    });
    const annotated = annotate(built.graph, rules);

    const result = {
      file,
      line,
      sources: annotated.sources
        .filter((item) => item.range.start.line === line)
        .map((item) => ({ id: item.sourceId, label: item.label, kinds: item.kinds })),
      sanitizers: annotated.sanitizers
        .filter((item) => item.range.start.line === line)
        .map((item) => ({
          id: item.sanitizerId,
          valid: item.valid,
          ...(item.invalidReason === undefined ? {} : { reason: item.invalidReason }),
        })),
      sinks: annotated.sinks
        .filter((item) => item.range.start.line === line)
        .map((item) => ({ id: item.sinkId, severity: item.severity, message: item.message })),
    };

    if (json) {
      io.stdout(`${JSON.stringify(result, null, 2)}\n`);
      return EXIT_OK;
    }

    io.stdout(`${file}:${line} の判定\n`);
    io.stdout(`  ソース    : ${result.sources.length === 0 ? 'なし' : result.sources.map((s) => `${s.id} (${s.label})`).join(', ')}\n`);
    io.stdout(`  サニタイザ: ${result.sanitizers.length === 0 ? 'なし' : result.sanitizers.map((s) => `${s.id}${s.valid ? '' : ' (無効)'}`).join(', ')}\n`);
    io.stdout(`  シンク    : ${result.sinks.length === 0 ? 'なし' : result.sinks.map((s) => `${s.id} [${s.severity}]`).join(', ')}\n`);
    return EXIT_OK;
  } catch (error) {
    io.stderr(`エラー: 解析できませんでした: ${describe(error)}\n`);
    return EXIT_ERROR;
  }
}

/** `scan` コマンド: 解析してレポートを出力する。 */
async function runScan(io: CliIo, command: Extract<CliCommand, { kind: 'scan' }>): Promise<number> {
  try {
    const config = await resolveCliConfig(command);
    const started = Date.now();

    const result = await scan({
      root: command.target,
      include: command.include,
      exclude: command.exclude,
      // 設定が解決できなかった場合はエンジン側の組み込み既定に委ねる。
      ...(config === undefined ? {} : { config }),
      ...(command.quiet
        ? {}
        : {
            onProgress: (event) => {
              if (event.total > 0 && event.current === event.total) {
                io.stderr(`  ${event.phase}: ${event.current}/${event.total}${event.detail === undefined ? '' : ` (${event.detail})`}\n`);
              }
            },
          }),
    });

    const reporter = createReporter(command.format, {
      color: command.color,
      informationUri: REPOSITORY_URL,
    });
    const rendered = reporter.render(result);

    if (command.output === undefined) {
      io.stdout(rendered.endsWith('\n') ? rendered : `${rendered}\n`);
    } else {
      await writeFile(command.output, rendered, 'utf8');
      io.stdout(`レポートを書き出しました: ${command.output}\n`);
    }

    const fatal = result.diagnostics.filter((diagnostic) => diagnostic.level === 'error');

    // 解析に失敗した場合は --quiet でも必ず知らせる。
    // 「静かに成功したように見える失敗」は CI で最も危険な挙動なので避ける。
    for (const diagnostic of fatal) {
      io.stderr(`[error] ${diagnostic.message}${diagnostic.file === undefined ? '' : ` (${diagnostic.file})`}\n`);
    }
    if (!command.quiet) {
      io.stderr(`${summarize(result)}\n`);
      void started;
    }

    // 解析そのものが失敗した場合（対象が存在しない等）は、
    // 「脆弱性なし」と区別できるよう終了コード 2 を返す。
    // CI がこの 2 つを取り違えると、静かに素通りしてしまう。
    if (fatal.length > 0) {
      return EXIT_ERROR;
    }

    return shouldFail(result, command.failOn) ? EXIT_FINDINGS : EXIT_OK;
  } catch (error) {
    io.stderr(`エラー: ${describe(error)}\n`);
    return EXIT_ERROR;
  }
}

/** CLI フラグを反映した設定を解決する。 */
async function resolveCliConfig(command: Extract<CliCommand, { kind: 'scan' }>): Promise<TaintConfig | undefined> {
  try {
    const { resolveConfig } = await import('../config/loader.js');
    return await resolveConfig({
      root: command.target,
      ...(command.configPath === undefined ? {} : { configPath: command.configPath }),
      overrides: {
        format: command.format,
        ...(command.output === undefined ? {} : { output: command.output }),
        failOn: command.failOn,
        ...(command.maxCallDepth === undefined ? {} : { maxCallDepth: command.maxCallDepth }),
      },
    });
  } catch (error) {
    // 実装が未完了、または設定が壊れている場合は組み込み既定で続行する。
    // 黙って落とさず、必ず理由を出す。
    if (isNotImplemented(error)) {
      return undefined;
    }
    throw error;
  }
}

function isNotImplemented(error: unknown): boolean {
  return error instanceof Error && /not implemented|未実装/i.test(error.message);
}

function describe(error: unknown): string {
  if (error instanceof Error) {
    const hint = (error as { hint?: string }).hint;
    return hint === undefined ? error.message : `${error.message}（${hint}）`;
  }
  return String(error);
}

/** 組み込みルールを読み込む（循環 import を避けるため動的 import）。 */
async function loadBuiltin(): Promise<typeof import('../rules/builtin.js')> {
  return import('../rules/builtin.js');
}

export { CliError };
export type { Severity };
