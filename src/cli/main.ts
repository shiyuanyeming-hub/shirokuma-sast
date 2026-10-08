#!/usr/bin/env node
/**
 * `shirokuma` コマンドのエントリポイント。
 *
 * 例外はここで捕捉し、スタックトレースではなく読めるメッセージを出す。
 * 予期しない例外でも終了コード 2 を返し、CI が「解析失敗」と
 * 「脆弱性あり」を取り違えないようにする。
 */
import { run } from './scan-command.js';

const write = (stream: NodeJS.WriteStream) => (text: string): void => {
  stream.write(text);
};

async function main(): Promise<void> {
  const code = await run(process.argv.slice(2), {
    stdout: write(process.stdout),
    stderr: write(process.stderr),
  });
  process.exitCode = code;
}

main().catch((error: unknown) => {
  process.stderr.write(`予期しないエラー: ${error instanceof Error ? (error.stack ?? error.message) : String(error)}\n`);
  process.exitCode = 2;
});
