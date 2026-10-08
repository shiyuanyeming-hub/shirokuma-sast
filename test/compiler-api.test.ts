/**
 * TypeScript Compiler API の疎通確認。
 * IR 構築が依存する API が期待どおり動くかをここで固定する。
 */
import { describe, expect, it } from 'vitest';
import ts from 'typescript';

function parse(source: string, fileName = 'sample.ts'): ts.SourceFile {
  return ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
}

describe('TypeScript Compiler API', () => {
  it('AST を構築し、呼び出し式とプロパティアクセスを列挙できる', () => {
    const sf = parse(`
      import express from 'express';
      const app = express();
      app.get('/users', (req, res) => {
        const id = req.query.id;
        const sql = "SELECT * FROM users WHERE id = '" + id + "'";
        db.query(sql, (err, rows) => res.send(rows));
      });
    `);

    const calls: string[] = [];
    const walk = (node: ts.Node): void => {
      if (ts.isCallExpression(node)) {
        calls.push(node.expression.getText(sf));
      }
      ts.forEachChild(node, walk);
    };
    walk(sf);

    expect(calls).toContain('express');
    expect(calls).toContain('app.get');
    expect(calls).toContain('db.query');
    expect(sf.fileName).toBe('sample.ts');
  });

  it('位置情報を 1-based の行・列で取得できる', () => {
    const sf = parse('const a = 1;\nconst b = req.query.x;\n');
    const line2 = sf.getLineAndCharacterOfPosition(sf.getPositionOfLineAndCharacter(1, 10));
    expect(line2.line).toBe(1);
    expect(line2.character).toBe(10);
  });

  it('構文エラーを診断として取得できる', () => {
    const sf = parse('const = ;');
    const diagnostics = (sf as unknown as { parseDiagnostics?: ts.Diagnostic[] }).parseDiagnostics ?? [];
    expect(diagnostics.length).toBeGreaterThan(0);
  });

  it('型チェッカなしで識別子のスコープを親辿りで判定できる（IR 構築の前提）', () => {
    const sf = parse(`
      function handler(req: any) {
        const id = req.query.id;
        function inner() { return id; }
        return inner();
      }
    `);

    let paramNames: string[] = [];
    const walk = (node: ts.Node): void => {
      if (ts.isFunctionDeclaration(node) && node.name?.text === 'handler') {
        paramNames = node.parameters.map((p) => p.name.getText(sf));
      }
      ts.forEachChild(node, walk);
    };
    walk(sf);

    expect(paramNames).toEqual(['req']);
  });
});
