/**
 * パターン照合器の挙動を固定する。
 *
 * ここで検証しているのは「ルールがどの式に一致するか」というエンジンの土台であり、
 * 接頭辞一致・接尾辞一致・動的プロパティ・呼び出し名の扱いを 1 件ずつ固定する。
 */
import { describe, expect, it } from 'vitest';
import type { ResolvedExpression } from '../../src/rules/annotate-contract.js';
import {
  compareSpecificity,
  isConstantArgumentText,
  isEmptyExpression,
  isLiteralText,
  matchesPattern,
  matchMostSpecific,
  parseExpression,
  patternSpecificity,
  resolveMemberChain,
} from '../../src/rules/match.js';

/** 式を組み立てるヘルパー（テストの可読性のため）。 */
function expression(overrides: Partial<ResolvedExpression> & Pick<ResolvedExpression, 'isCall' | 'argTexts' | 'firstArgIsLiteral'>): ResolvedExpression {
  return { ...overrides };
}

describe('resolveMemberChain', () => {
  it('ドット区切りのメンバ式をそのまま返す', () => {
    expect(resolveMemberChain('req.query.id')).toBe('req.query.id');
  });

  it('単一セグメントも解決する', () => {
    expect(resolveMemberChain('req')).toBe('req');
  });

  it('オプショナルチェーンと非 null アサーションを正規化する', () => {
    expect(resolveMemberChain('req?.query?.id')).toBe('req.query.id');
    expect(resolveMemberChain('req!.query')).toBe('req.query');
  });

  it('分割 require をモジュール名へ解決する', () => {
    expect(resolveMemberChain("require('child_process').exec")).toBe('child_process.exec');
    expect(resolveMemberChain('require("http").request')).toBe('http.request');
  });

  it('動的 require は解決しない（未解決として undefined）', () => {
    expect(resolveMemberChain('require(moduleName).exec')).toBeUndefined();
  });

  it('文字列リテラル添字はセグメントとして解決する', () => {
    expect(resolveMemberChain("req['query']")).toBe('req.query');
  });

  it('動的添字はワイルドカードセグメント `*` になる', () => {
    expect(resolveMemberChain('req[userKey]')).toBe('req.*');
    expect(resolveMemberChain('data[key][other]')).toBe('data.*.*');
  });

  it('丸括弧によるグルーピングを解決する', () => {
    expect(resolveMemberChain('(req.query).id')).toBe('req.query.id');
  });

  it('末尾のセミコロン・`as` 注釈・先頭の await を取り除く', () => {
    expect(resolveMemberChain('await db.query;')).toBe('db.query');
    expect(resolveMemberChain('req.query as string')).toBe('req.query');
  });

  it('演算子を含む式は解決しない', () => {
    expect(resolveMemberChain('sql + name')).toBeUndefined();
    expect(resolveMemberChain('a || b')).toBeUndefined();
    expect(resolveMemberChain('fn()')).toBeUndefined();
  });

  it('文字列以外の値からも解決する（IR ノード / AST ノード）', () => {
    expect(resolveMemberChain({ label: 'req.query.id' })).toBe('req.query.id');
    expect(resolveMemberChain({ text: 'ctx.request.body' })).toBe('ctx.request.body');
    expect(resolveMemberChain({ getText: () => 'process.env.HOME' })).toBe('process.env.HOME');
  });

  it('解決できない入力は undefined を返す', () => {
    expect(resolveMemberChain(undefined)).toBeUndefined();
    expect(resolveMemberChain(null)).toBeUndefined();
    expect(resolveMemberChain(42)).toBeUndefined();
    expect(resolveMemberChain({})).toBeUndefined();
  });
});

describe('parseExpression', () => {
  it('呼び出し式を callee と引数へ分解する', () => {
    const expr = parseExpression('db.query(sql)');
    expect(expr.member).toBe('db.query');
    expect(expr.last).toBe('query');
    expect(expr.isCall).toBe(true);
    expect(expr.argTexts).toEqual(['sql']);
    expect(expr.firstArgIsLiteral).toBe(false);
  });

  it('ネストした引数とクォート内のカンマを正しく分割する', () => {
    const expr = parseExpression('fn({ a: 1 }, "x, y", g(1, 2))');
    expect(expr.argTexts).toEqual(['{ a: 1 }', '"x, y"', 'g(1, 2)']);
  });

  it('アロー関数の引数を 1 つの引数として扱う', () => {
    const expr = parseExpression('arr.map((x) => sink(x))');
    expect(expr.member).toBe('arr.map');
    expect(expr.argTexts).toEqual(['(x) => sink(x)']);
  });

  it('文字列リテラルの第 1 引数を検出する', () => {
    expect(parseExpression("db.query('SELECT 1')").firstArgIsLiteral).toBe(true);
    expect(parseExpression('db.query(`SELECT 1`)').firstArgIsLiteral).toBe(true);
    expect(parseExpression('db.query(`SELECT ${id}`)').firstArgIsLiteral).toBe(false);
    expect(parseExpression('db.query(sql)').firstArgIsLiteral).toBe(false);
  });

  it('`new` 式を呼び出しとして解決する', () => {
    const expr = parseExpression('new Function(code)');
    expect(expr.member).toBe('Function');
    expect(expr.identifier).toBe('Function');
    expect(expr.isCall).toBe(true);
  });

  it('連鎖呼び出しは最初の呼び出しを代表として解決する', () => {
    const expr = parseExpression('db.query(sql).then(cb)');
    expect(expr.member).toBe('db.query');
    expect(expr.argTexts).toEqual(['sql']);
  });

  it('単一セグメントの式は identifier と member の両方を持つ', () => {
    const expr = parseExpression('req');
    expect(expr.identifier).toBe('req');
    expect(expr.member).toBe('req');
    expect(expr.isCall).toBe(false);
  });

  it('メンバ式の identifier は未設定（裸の識別子ではないため）', () => {
    expect(parseExpression('req.query.id').identifier).toBeUndefined();
    expect(isEmptyExpression(parseExpression('req.query.id'))).toBe(false);
  });

  it('呼び出しの途中で切り詰められたラベルでも引数を復元する', () => {
    const arg0 = "'SELECT id, name FROM users WHERE id = ? AND tenant_id = ?'";
    const line = `db.query(${arg0}, [id, tenant, status])`;
    const truncated = `${line.slice(0, 80)}…`;
    expect(line.length).toBeGreaterThan(80);
    expect(truncated.indexOf(arg0)).toBe(9);
    const expr = parseExpression(truncated);
    expect(expr.member).toBe('db.query');
    expect(expr.argTexts[0]).toBe(arg0);
    expect(expr.firstArgIsLiteral).toBe(true);
  });

  it('呼び出しの直後で切り詰められたラベル（末尾が `…`）も呼び出しとして扱う', () => {
    const line = "db.query('SELECT 1', [id])";
    const expr = parseExpression(`${line}…`);
    expect(expr.member).toBe('db.query');
    expect(expr.isCall).toBe(true);
    expect(expr.argTexts).toEqual(["'SELECT 1'", '[id]']);
    expect(expr.firstArgIsLiteral).toBe(true);
  });

  it('切り詰めで第 1 引数自体が欠けた場合は非リテラルとして扱う', () => {
    const line = "db.query('SELECT id, name FROM users WHERE id = ? AND status = ? and created_at > ?', [id])";
    const truncated = `${line.slice(0, 60)}…`;
    expect(parseExpression(truncated).firstArgIsLiteral).toBe(false);
  });

  it('解決できない式では fallback を試す', () => {
    const expr = parseExpression('sql + id', { fallback: 'db.query(sql + id)' });
    expect(expr.member).toBe('db.query');
    expect(expr.argTexts).toEqual(['sql + id']);
  });

  it('解決できない式は空の式になる', () => {
    expect(isEmptyExpression(parseExpression('foo(bar)(baz)'))).toBe(true);
    expect(isEmptyExpression(parseExpression('a + b'))).toBe(true);
  });

  it('kind が call なら括弧が無くても呼び出しとして扱う', () => {
    expect(parseExpression('exec', { isCall: true }).isCall).toBe(true);
  });
});

describe('isLiteralText / isConstantArgumentText', () => {
  it('文字列リテラルと補間なしテンプレートをリテラルと判定する', () => {
    expect(isLiteralText("'SELECT 1'")).toBe(true);
    expect(isLiteralText('"SELECT 1"')).toBe(true);
    expect(isLiteralText('`SELECT 1`')).toBe(true);
    expect(isLiteralText('`SELECT ${id}`')).toBe(false);
    expect(isLiteralText('sql')).toBe(false);
    expect(isLiteralText("'a' + b")).toBe(false);
  });

  it('エスケープされた `${` は補間として扱わない', () => {
    expect(isLiteralText('`a\\${b}`')).toBe(true);
  });

  it('丸括弧で囲まれたリテラルもリテラルと判定する', () => {
    expect(isLiteralText("( 'x' )")).toBe(true);
    expect(isLiteralText('(a)')).toBe(false);
  });

  it('constant-argument は数値・真偽値・null も定数として扱う', () => {
    expect(isConstantArgumentText('42')).toBe(true);
    expect(isConstantArgumentText('true')).toBe(true);
    expect(isConstantArgumentText('null')).toBe(true);
    expect(isConstantArgumentText("'/safe/base'")).toBe(true);
    expect(isConstantArgumentText('baseDir')).toBe(false);
    expect(isConstantArgumentText('getBase()')).toBe(false);
  });
});

describe('matchesPattern', () => {
  const reqQueryId = parseExpression('req.query.id');

  it('member は接頭辞一致で長い方へも一致する', () => {
    expect(matchesPattern({ member: 'req.query' }, reqQueryId)).toBe(true);
    expect(matchesPattern({ member: 'req.query.id' }, reqQueryId)).toBe(true);
    expect(matchesPattern({ member: 'req' }, reqQueryId)).toBe(true);
    expect(matchesPattern({ member: 'req.query.id.name' }, reqQueryId)).toBe(false);
  });

  it('セグメント境界を越えて一致しない', () => {
    expect(matchesPattern({ member: 'res.send' }, parseExpression('res.sendFile'))).toBe(false);
    expect(matchesPattern({ member: 'child_process.exec' }, parseExpression('child_process.execSync'))).toBe(false);
  });

  it('先頭 `.` のパターンは接尾辞一致（レシーバ不定のプロパティ）', () => {
    expect(matchesPattern({ member: '.innerHTML' }, parseExpression('el.innerHTML'))).toBe(true);
    expect(matchesPattern({ member: '.innerHTML' }, parseExpression('document.body.innerHTML'))).toBe(true);
    expect(matchesPattern({ member: '.innerHTML' }, parseExpression('el.textContent'))).toBe(false);
  });

  it('identifier は裸の識別子にのみ一致する', () => {
    expect(matchesPattern({ identifier: 'req' }, parseExpression('req'))).toBe(true);
    expect(matchesPattern({ identifier: 'req' }, parseExpression('req.query'))).toBe(false);
    expect(matchesPattern({ identifier: 'request' }, parseExpression('req'))).toBe(false);
  });

  it('call は呼び出し式の単純名に一致する（レシーバ不定のメソッドを含む）', () => {
    expect(matchesPattern({ call: 'find' }, parseExpression('User.find(filter)'))).toBe(true);
    expect(matchesPattern({ call: 'exec' }, parseExpression('exec(cmd)'))).toBe(true);
    expect(matchesPattern({ call: 'query' }, parseExpression('db.query(sql)'))).toBe(true);
  });

  it('call は呼び出し式でなければ一致しない', () => {
    expect(matchesPattern({ call: 'find' }, parseExpression('User.find'))).toBe(false);
  });

  it('member と call を併記すると両方を要求する', () => {
    expect(matchesPattern({ member: 'res.send', call: 'send' }, parseExpression('res.send(body)'))).toBe(true);
    expect(matchesPattern({ member: 'res.send', call: 'send' }, parseExpression('res.send'))).toBe(false);
  });

  it('動的プロパティは allowDynamic のときだけ既知の規則へ一致する', () => {
    const dynamic = parseExpression('req[userKey]');
    expect(dynamic.member).toBe('req.*');
    expect(matchesPattern({ member: 'req.query' }, dynamic)).toBe(false);
    expect(matchesPattern({ member: 'req.query', allowDynamic: true }, dynamic)).toBe(true);
  });

  it('パターン側の `*` は任意の 1 セグメントに一致する', () => {
    expect(matchesPattern({ member: 'req.*' }, parseExpression('req.query'))).toBe(true);
    expect(matchesPattern({ member: 'req.*.id' }, parseExpression('req.query.id'))).toBe(true);
    expect(matchesPattern({ member: 'req.*' }, parseExpression('res.query'))).toBe(false);
  });

  it('条件を 1 つも持たないパターンは何にも一致しない', () => {
    expect(matchesPattern({}, reqQueryId)).toBe(false);
  });
});

describe('matchMostSpecific / patternSpecificity', () => {
  it('最も長く一致したパターンを返す', () => {
    const patterns = [{ id: 'short', member: 'req.query' }, { id: 'long', member: 'req.query.id' }] as const;
    expect(matchMostSpecific(patterns, parseExpression('req.query.id'))?.id).toBe('long');
  });

  it('member 付きのパターンは identifier のみのパターンより優先される', () => {
    const patterns = [{ id: 'identifier', identifier: 'req' }, { id: 'member', member: 'req.query' }] as const;
    expect(matchMostSpecific(patterns, parseExpression('req.query'))?.id).toBe('member');
  });

  it('member 付きは call のみのパターンより優先される', () => {
    const patterns = [{ id: 'call', call: 'exec' }, { id: 'member', member: 'child_process.exec' }] as const;
    expect(matchMostSpecific(patterns, parseExpression('child_process.exec(cmd)'))?.id).toBe('member');
  });

  it('具体度が同じときは先に宣言されたものを返す', () => {
    const patterns = [{ id: 'first', call: 'find' }, { id: 'second', call: 'find' }] as const;
    expect(matchMostSpecific(patterns, parseExpression('User.find(x)'))?.id).toBe('first');
  });

  it('一致が無ければ undefined を返す', () => {
    expect(matchMostSpecific([{ member: 'db.query' }], parseExpression('req.query'))).toBeUndefined();
  });

  it('スコアは member セグメント数 → 文字数 → identifier → call の順で比較する', () => {
    expect(compareSpecificity(patternSpecificity({ member: 'a.b' }), patternSpecificity({ member: 'a' }))).toBeGreaterThan(0);
    expect(compareSpecificity(patternSpecificity({ member: '.innerHTML' }), patternSpecificity({ identifier: 'x' }))).toBeGreaterThan(0);
    expect(compareSpecificity(patternSpecificity({ call: 'find' }), patternSpecificity({ call: 'find' }))).toBe(0);
  });
});

describe('ResolvedExpression の形', () => {
  it('空の式は member も identifier も持たない', () => {
    const empty = expression({ isCall: false, argTexts: [], firstArgIsLiteral: false });
    expect(isEmptyExpression(empty)).toBe(true);
  });
});
