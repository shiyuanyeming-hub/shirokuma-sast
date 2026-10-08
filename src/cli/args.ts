/**
 * `shirokuma` CLI の引数解析。
 *
 * 依存を増やさないため、必要な範囲のパーサを自前で実装している。
 * 解析結果は判別可能な共用体として返すので、呼び出し側は
 * すべての分岐を網羅できる（`default` に逃げる必要がない）。
 */
import type { OutputConfig, Severity } from '../types.js';

export const CLI_NAME = 'shirokuma';
export const DEFAULT_COMMAND = 'scan';

export interface ScanCommand {
  readonly kind: 'scan';
  /** 解析対象のパス（既定はカレントディレクトリ）。 */
  readonly target: string;
  readonly format: OutputConfig['format'];
  readonly output?: string;
  readonly failOn: Severity | 'none';
  readonly configPath?: string;
  readonly include: readonly string[];
  readonly exclude: readonly string[];
  readonly color: boolean;
  readonly quiet: boolean;
  readonly maxCallDepth?: number;
}

export interface RulesCommand {
  readonly kind: 'rules';
  readonly json: boolean;
}

export interface ExplainCommand {
  readonly kind: 'explain';
  /** ファイルパス。 */
  readonly file: string;
  readonly line: number;
  readonly json: boolean;
}

export interface HelpCommand {
  readonly kind: 'help';
  readonly topic?: string;
}

export interface VersionCommand {
  readonly kind: 'version';
}

export type CliCommand = ScanCommand | RulesCommand | ExplainCommand | HelpCommand | VersionCommand;

/** 引数解析の失敗。CLI はこれを捕捉して使い方と終了コード 2 を返す。 */
export class CliError extends Error {
  constructor(
    message: string,
    readonly hint?: string,
  ) {
    super(message);
    this.name = 'CliError';
  }
}

const FORMATS: readonly OutputConfig['format'][] = ['pretty', 'json', 'sarif', 'markdown'];
const SEVERITIES: readonly (Severity | 'none')[] = ['error', 'warning', 'note', 'none'];

/** 使い方の全文。`--help` と引数エラーの両方で使う。 */
export const USAGE = `${CLI_NAME} — TypeScript/JavaScript 向け 汚染解析 SAST

使い方:
  ${CLI_NAME} [scan] [パス] [オプション]
  ${CLI_NAME} rules [--json]
  ${CLI_NAME} explain <ファイル>:<行> [--json]
  ${CLI_NAME} --help | --version

オプション:
  -f, --format <pretty|json|sarif|markdown>  出力形式（既定 pretty）
  -o, --output <ファイル>                    結果をファイルへ書き出す
      --config <ファイル>                    設定ファイル（既定は .shirokuma.yml を探索）
      --include <glob>                       対象を絞る（複数指定可）
      --exclude <glob>                       除外する（複数指定可）
      --fail-on <error|warning|note|none>    この重要度以上で終了コード 1（既定 error）
      --max-call-depth <数値>                呼び出し文脈の深さの上限
      --no-color                             色付き出力を無効化
  -q, --quiet                                進捗とサマリを抑制
  -h, --help                                 この使い方を表示
  -v, --version                              バージョンを表示

終了コード:
  0  検出なし、または --fail-on 未満
  1  --fail-on 以上の検出あり
  2  引数・設定・実行時のエラー
`;

/** `--key=value` と `--key value` の両方を受ける。 */
function splitOption(argument: string): { key: string; inlineValue?: string } {
  const equalIndex = argument.indexOf('=');
  if (equalIndex === -1) {
    return { key: argument };
  }
  return { key: argument.slice(0, equalIndex), inlineValue: argument.slice(equalIndex + 1) };
}

function requireValue(key: string, inlineValue: string | undefined, next: string | undefined): string {
  if (inlineValue !== undefined) {
    if (inlineValue.length === 0) {
      throw new CliError(`${key} には値が必要です`);
    }
    return inlineValue;
  }
  if (next === undefined || next.startsWith('-')) {
    throw new CliError(`${key} には値が必要です`, `例: ${key} ${key === '--format' ? 'sarif' : '値'}`);
  }
  return next;
}

/** コマンドライン引数を解析する。 */
export function parseArgs(argv: readonly string[]): CliCommand {
  const args = [...argv];
  if (args.length === 0) {
    return defaultScan();
  }

  const [first, ...rest] = args;

  if (first === undefined) {
    return defaultScan();
  }
  if (first === '--help' || first === '-h' || first === 'help') {
    return { kind: 'help', ...(rest[0] === undefined ? {} : { topic: rest[0] }) };
  }
  if (first === '--version' || first === '-v' || first === 'version') {
    return { kind: 'version' };
  }
  if (first === 'rules') {
    return { kind: 'rules', json: rest.includes('--json') };
  }
  if (first === 'explain') {
    return parseExplain(rest);
  }

  const scanArgs = first === 'scan' ? rest : args;
  return parseScan(scanArgs);
}

function defaultScan(): ScanCommand {
  return {
    kind: 'scan',
    target: '.',
    format: 'pretty',
    failOn: 'error',
    include: [],
    exclude: [],
    color: process.stdout.isTTY === true && process.env['NO_COLOR'] === undefined,
    quiet: false,
  };
}

function parseExplain(args: readonly string[]): ExplainCommand {
  const positional = args.filter((argument) => !argument.startsWith('-'));
  const target = positional[0];
  if (target === undefined) {
    throw new CliError('explain には <ファイル>:<行> が必要です', `例: ${CLI_NAME} explain src/app.ts:42`);
  }
  const lastColon = target.lastIndexOf(':');
  if (lastColon === -1) {
    throw new CliError(`位置の指定が不正です: ${target}`, `例: ${CLI_NAME} explain src/app.ts:42`);
  }
  const file = target.slice(0, lastColon);
  const line = Number.parseInt(target.slice(lastColon + 1), 10);
  if (!Number.isInteger(line) || line <= 0) {
    throw new CliError(`行番号が不正です: ${target.slice(lastColon + 1)}`);
  }
  return { kind: 'explain', file, line, json: args.includes('--json') };
}

function parseScan(args: readonly string[]): ScanCommand | HelpCommand {
  const command: {
    target: string;
    format: OutputConfig['format'];
    output?: string;
    failOn: Severity | 'none';
    configPath?: string;
    include: string[];
    exclude: string[];
    color: boolean;
    quiet: boolean;
    maxCallDepth?: number;
  } = {
    target: '.',
    format: 'pretty',
    failOn: 'error',
    include: [],
    exclude: [],
    color: process.stdout.isTTY === true && process.env['NO_COLOR'] === undefined,
    quiet: false,
  };

  let index = 0;
  while (index < args.length) {
    const argument = args[index];
    if (argument === undefined) {
      break;
    }
    const { key, inlineValue } = splitOption(argument);
    const next = args[index + 1];

    switch (key) {
      case '-f':
      case '--format': {
        const value = requireValue(key, inlineValue, next);
        if (!FORMATS.includes(value as OutputConfig['format'])) {
          throw new CliError(`未知の出力形式です: ${value}`, `利用可能: ${FORMATS.join(', ')}`);
        }
        command.format = value as OutputConfig['format'];
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '-o':
      case '--output': {
        command.output = requireValue(key, inlineValue, next);
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '--config': {
        command.configPath = requireValue(key, inlineValue, next);
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '--fail-on': {
        const value = requireValue(key, inlineValue, next);
        if (!SEVERITIES.includes(value as Severity | 'none')) {
          throw new CliError(`未知の重要度です: ${value}`, `利用可能: ${SEVERITIES.join(', ')}`);
        }
        command.failOn = value as Severity | 'none';
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '--max-call-depth': {
        const value = Number.parseInt(requireValue(key, inlineValue, next), 10);
        if (!Number.isInteger(value) || value < 0) {
          throw new CliError(`--max-call-depth には 0 以上の整数が必要です`);
        }
        command.maxCallDepth = value;
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '--include': {
        command.include.push(requireValue(key, inlineValue, next));
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '--exclude': {
        command.exclude.push(requireValue(key, inlineValue, next));
        index += inlineValue === undefined ? 2 : 1;
        break;
      }
      case '--no-color': {
        command.color = false;
        index += 1;
        break;
      }
      case '-q':
      case '--quiet': {
        command.quiet = true;
        index += 1;
        break;
      }
      case '-h':
      case '--help': {
        // 解析の途中でも使い方を出せるよう、専用の戻り値にする。
        return { kind: 'help' };
      }
      default: {
        if (key.startsWith('-')) {
          throw new CliError(`未知のオプションです: ${key}`, `${CLI_NAME} --help で使い方を表示します`);
        }
        command.target = argument;
        index += 1;
        break;
      }
    }
  }

  return {
    kind: 'scan',
    target: command.target,
    format: command.format,
    failOn: command.failOn,
    include: command.include,
    exclude: command.exclude,
    color: command.color,
    quiet: command.quiet,
    ...(command.output === undefined ? {} : { output: command.output }),
    ...(command.configPath === undefined ? {} : { configPath: command.configPath }),
    ...(command.maxCallDepth === undefined ? {} : { maxCallDepth: command.maxCallDepth }),
  };
}
