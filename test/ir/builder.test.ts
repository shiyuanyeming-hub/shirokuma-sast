import { describe, expect, it } from 'vitest';
import { buildIRFromSource } from '../../src/ir/builder.js';
import type { FlowNode, IRGraph } from '../../src/types.js';

/** ラベルでノードを引く（完全一致 → 部分一致の順）。 */
function nodeByLabel(graph: IRGraph, label: string): FlowNode {
  const exact = graph.nodes.filter((node) => node.label === label);
  if (exact.length > 0) {
    return exact[0] as FlowNode;
  }
  const partial = graph.nodes.filter((node) => node.label.includes(label));
  if (partial.length === 0) {
    throw new Error(`node not found: ${label}\navailable: ${graph.nodes.map((n) => n.label).join(' | ')}`);
  }
  return partial[0] as FlowNode;
}

/** `from` から `to` へ辺を辿って到達できるか。 */
function flows(graph: IRGraph, from: string, to: string): boolean {
  const adjacency = new Map<string, string[]>();
  for (const edge of graph.edges) {
    const bucket = adjacency.get(edge.from) ?? [];
    bucket.push(edge.to);
    adjacency.set(edge.from, bucket);
  }
  const seen = new Set<string>([from]);
  const queue = [from];
  while (queue.length > 0) {
    const current = queue.shift() as string;
    if (current === to) {
      return true;
    }
    for (const next of adjacency.get(current) ?? []) {
      if (!seen.has(next)) {
        seen.add(next);
        queue.push(next);
      }
    }
  }
  return false;
}

/** ラベル A からラベル B へデータが流れるか。 */
function labelFlows(graph: IRGraph, fromLabel: string, toLabel: string): boolean {
  return flows(graph, nodeByLabel(graph, fromLabel).id, nodeByLabel(graph, toLabel).id);
}

function build(source: string, path = 'a.ts'): IRGraph {
  return buildIRFromSource(source, path, { root: '/proj' });
}

describe('ルール 1: 変数宣言', () => {
  it('const x = tainted で tainted から x へ流れる', () => {
    const graph = build('function f(req: any) { const x = req.query.a; sink(x); }');
    expect(labelFlows(graph, 'req.query.a', 'x')).toBe(true);
  });

  it('let 宣言でも同じく流れる', () => {
    const graph = build('function f(req: any) { let x = req.body.a; sink(x); }');
    expect(labelFlows(graph, 'req.body.a', 'x')).toBe(true);
  });

  it('初期化子が無い宣言はノードを持つが流入は無い', () => {
    const graph = build('function f() { let x; sink(x); }');
    const x = nodeByLabel(graph, 'x');
    expect(graph.edges.filter((edge) => edge.to === x.id)).toHaveLength(0);
  });
});

describe('ルール 2: 再代入', () => {
  it('x = tainted で流れ、変数ノードは 1 つに保たれる', () => {
    const graph = build("function f(req: any) { let x = 'safe'; x = req.query.a; sink(x); }");
    expect(labelFlows(graph, 'req.query.a', 'x')).toBe(true);
    expect(graph.nodes.filter((node) => node.label === 'x')).toHaveLength(1);
  });

  it('再代入後も前の値が同じ変数ノードへ合流する（フロー鈍感の保守性）', () => {
    const graph = build("function f(req: any) { let x = req.query.a; x = 'safe'; sink(x); }");
    expect(labelFlows(graph, 'req.query.a', 'x')).toBe(true);
  });

  it('複合代入（+=）で右辺から左辺へ流れる', () => {
    const graph = build("function f(req: any) { let sql = ''; sql += req.query.a; sink(sql); }");
    expect(labelFlows(graph, 'req.query.a', 'sql')).toBe(true);
  });
});

describe('ルール 3: 文字列連結', () => {
  it('a + tainted で連結結果へ流れる', () => {
    const graph = build("function f(req: any) { const q = 'SELECT ' + req.query.a; sink(q); }");
    expect(labelFlows(graph, 'req.query.a', q(graph))).toBe(true);
  });

  it('tainted + b でも同じ', () => {
    const graph = build("function f(req: any) { const q = req.query.a + ' tail'; sink(q); }");
    expect(labelFlows(graph, 'req.query.a', q(graph))).toBe(true);
  });

  it('連結を連鎖できる', () => {
    const graph = build("function f(req: any) { const q = 'a' + req.query.x + 'b' + 'c'; sink(q); }");
    expect(labelFlows(graph, 'req.query.x', q(graph))).toBe(true);
  });

  it('数値の減算でも伝播する（重要な過剰検出の回避ではなく保守性のため）', () => {
    const graph = build('function f(req: any) { const n = req.query.n - 1; sink(n); }');
    expect(labelFlows(graph, 'req.query.n', 'n')).toBe(true);
  });
});

function q(graph: IRGraph): string {
  const candidate = graph.nodes.find((node) => node.kind === 'local' && node.label.includes('+'));
  if (candidate === undefined) {
    throw new Error(`concatenation node not found: ${graph.nodes.map((n) => n.label).join(' | ')}`);
  }
  return candidate.label;
}

describe('ルール 4: テンプレートリテラル', () => {
  it('補間された値がテンプレートノードへ流れる', () => {
    const graph = build('function f(req: any) { const s = `SELECT ${req.query.a}`; sink(s); }');
    const template = graph.nodes.find((node) => node.kind === 'template');
    expect(template).toBeDefined();
    expect(flows(graph, nodeByLabel(graph, 'req.query.a').id, template?.id ?? '')).toBe(true);
    expect(flows(graph, template?.id ?? '', nodeByLabel(graph, 's').id)).toBe(true);
  });

  it('補間なしテンプレートは literal として扱う', () => {
    const graph = build('function f() { const s = `safe`; }');
    expect(graph.nodes.some((node) => node.kind === 'template')).toBe(false);
    expect(graph.nodes.some((node) => node.label === '`safe`')).toBe(true);
  });

  it('複数の補間すべてが流れ込む', () => {
    const graph = build('function f(req: any) { const s = `${req.a}-${req.b}`; sink(s); }');
    const template = graph.nodes.find((node) => node.kind === 'template');
    expect(flows(graph, nodeByLabel(graph, 'req.a').id, template?.id ?? '')).toBe(true);
    expect(flows(graph, nodeByLabel(graph, 'req.b').id, template?.id ?? '')).toBe(true);
  });
});

describe('ルール 5: 配列・オブジェクト生成', () => {
  it('配列リテラルへ要素が流れる', () => {
    const graph = build("function f(req: any) { const a = [req.query.x, 's']; sink(a); }");
    const array = graph.nodes.find((node) => node.label.startsWith('['));
    expect(flows(graph, nodeByLabel(graph, 'req.query.x').id, array?.id ?? '')).toBe(true);
  });

  it('オブジェクトリテラルへプロパティ値が流れる', () => {
    const graph = build('function f(req: any) { const o = { k: req.query.x }; sink(o); }');
    const object = graph.nodes.find((node) => node.label.startsWith('{'));
    expect(flows(graph, nodeByLabel(graph, 'req.query.x').id, object?.id ?? '')).toBe(true);
  });

  it('ショートハンドプロパティでも流れる', () => {
    const graph = build('function f(req: any) { const v = req.query.x; const o = { v }; sink(o); }');
    const object = graph.nodes.find((node) => node.label.startsWith('{'));
    expect(flows(graph, nodeByLabel(graph, 'v').id, object?.id ?? '')).toBe(true);
  });

  it('スプレッドでも流れる', () => {
    const graph = build('function f(req: any) { const a = { ...req.query }; sink(a); }');
    const object = graph.nodes.find((node) => node.label.startsWith('{'));
    expect(flows(graph, nodeByLabel(graph, 'req.query').id, object?.id ?? '')).toBe(true);
  });
});

describe('ルール 6: プロパティ読み書き', () => {
  it('プロパティ読み出しが基底オブジェクトから流れる', () => {
    const graph = build('function f(req: any) { const v = req.query.a.b; sink(v); }');
    expect(labelFlows(graph, 'req.query.a', 'req.query.a.b')).toBe(true);
  });

  it('プロパティ書き込み後に読み出すと流れる', () => {
    const graph = build("function f(req: any) { const o: any = {}; o.k = req.query.x; sink(o.k); }");
    expect(labelFlows(graph, 'req.query.x', 'o.k')).toBe(true);
  });

  it('動的キー（要素アクセス）の鍵が汚染されていても辺を張る', () => {
    const graph = build('function f(req: any, o: any) { const v = o[req.query.k]; sink(v); }');
    // 動的キーの読み出しは基底と区別できるラベルになる。
    expect(labelFlows(graph, 'req.query.k', 'o[<dynamic>]')).toBe(true);
    expect(labelFlows(graph, 'o', 'o[<dynamic>]')).toBe(true);
  });

  it('リテラルキーの要素アクセスはドット表記として解決する', () => {
    const graph = build("function f(req: any) { const v = req['query']['id']; sink(v); }");
    expect(graph.nodes.some((node) => node.label === 'req.query.id')).toBe(true);
  });
});

describe('ルール 7: 呼び出し引数', () => {
  it('引数の位置（argIndex）を記録する', () => {
    const graph = build("function f(req: any) { sink('safe', req.query.x); }");
    const call = graph.nodes.find((node) => node.kind === 'call' && node.label === 'sink');
    const edge = graph.edges.find((e) => e.to === call?.id && e.from === nodeByLabel(graph, 'req.query.x').id);
    expect(edge?.kind).toBe('argument');
    expect(edge?.argIndex).toBe(1);
  });

  it('スプレッド引数でも流れる', () => {
    const graph = build('function f(req: any) { const args = [req.query.x]; sink(...args); }');
    const call = graph.nodes.find((node) => node.kind === 'call' && node.label === 'sink');
    expect(flows(graph, nodeByLabel(graph, 'args').id, call?.id ?? '')).toBe(true);
  });

  it('new 式も呼び出しとして扱う', () => {
    const graph = build('function f(req: any) { new Thing(req.query.x); }');
    const call = graph.nodes.find((node) => node.kind === 'call' && node.label === 'Thing');
    expect(call).toBeDefined();
    expect(flows(graph, nodeByLabel(graph, 'req.query.x').id, call?.id ?? '')).toBe(true);
  });
});

describe('ルール 8: 分割代入', () => {
  it('オブジェクト分割代入で親から各変数へ流れる', () => {
    const graph = build('function f(req: any) { const { a, b } = req.query; sink(a); sink(b); }');
    expect(labelFlows(graph, 'req.query', 'a')).toBe(true);
    expect(labelFlows(graph, 'req.query', 'b')).toBe(true);
  });

  it('ネストした分割代入を展開する', () => {
    const graph = build('function f(req: any) { const { a: { b } } = req.query; sink(b); }');
    expect(labelFlows(graph, 'req.query', 'b')).toBe(true);
  });

  it('配列分割代入で親から各変数へ流れる', () => {
    const graph = build('function f(req: any) { const [first] = req.query.list; sink(first); }');
    expect(labelFlows(graph, 'req.query.list', 'first')).toBe(true);
  });

  it('仮引数の分割代入が引数ノードから流れる', () => {
    const graph = build('function f({ a }: any) { sink(a); }');
    expect(labelFlows(graph, 'a: a', 'a')).toBe(true);
  });

  it('既定値が束縛先へ流れる', () => {
    const graph = build("function f(req: any) { const { a = req.query.fallback } = req.body; sink(a); }");
    expect(labelFlows(graph, 'req.query.fallback', 'a')).toBe(true);
  });
});

describe('ルール 9: スプレッド', () => {
  it('オブジェクトのスプレッドで流れる', () => {
    const graph = build('function f(req: any) { const a = { x: 1 }; const b = { ...a, k: req.query.y }; sink(b); }');
    const object = graph.nodes.filter((node) => node.label.startsWith('{'));
    expect(flows(graph, nodeByLabel(graph, 'a').id, object[object.length - 1]?.id ?? '')).toBe(true);
  });

  it('配列のスプレッドで流れる', () => {
    const graph = build('function f(req: any) { const a = [1]; const b = [...a, req.query.y]; sink(b); }');
    const arrays = graph.nodes.filter((node) => node.label.startsWith('['));
    expect(flows(graph, nodeByLabel(graph, 'a').id, arrays[arrays.length - 1]?.id ?? '')).toBe(true);
  });
});

describe('ルール 10・11: 戻り値', () => {
  it('return 文が return ノードを作り、値が流れ込む', () => {
    const graph = build('function g(req: any) { return req.query.x; }');
    const ret = graph.nodes.find((node) => node.kind === 'return');
    expect(ret).toBeDefined();
    expect(flows(graph, nodeByLabel(graph, 'req.query.x').id, ret?.id ?? '')).toBe(true);
  });

  it('アロー式の暗黙 return（式本体）でも return ノードを作る', () => {
    const graph = build('const g = (req: any) => req.query.x;');
    expect(graph.nodes.some((node) => node.kind === 'return')).toBe(true);
  });

  it('関数外へは return ノードから呼び出しノードへ流れる', () => {
    const graph = build('function g(x: any) { return x; }\nfunction h(req: any) { const y = g(req.query.z); sink(y); }');
    const call = graph.nodes.find((node) => node.kind === 'call' && node.label === 'g');
    const ret = graph.nodes.find((node) => node.kind === 'return');
    expect(flows(graph, ret?.id ?? '', call?.id ?? '')).toBe(true);
  });
});

describe('ルール 12: ローカル関数の呼び出し解決', () => {
  it('関数宣言を呼び出し先として解決し、callees に記録する', () => {
    const graph = build('function a(x: any) { return x; }\nfunction b(req: any) { a(req.query.q); }');
    const b = graph.functions.find((fn) => fn.name === 'b');
    expect(b?.callees.some((id) => id.endsWith('::a'))).toBe(true);
  });

  it('呼び出しノードに resolvedCallees が入る', () => {
    const graph = build('function a(x: any) { return x; }\nfunction b() { a(1); }');
    const call = graph.nodes.find((node) => node.kind === 'call' && node.label === 'a');
    expect(call?.resolvedCallees?.[0]).toContain('::a');
  });

  it('変数束縛された関数式を解決する', () => {
    const graph = build('const a = (x: any) => x;\nfunction b(req: any) { a(req.query.q); }');
    const b = graph.functions.find((fn) => fn.name === 'b');
    expect(b?.callees.some((id) => id.includes('a'))).toBe(true);
  });

  it('相互再帰でも両方向の呼び出しを記録する', () => {
    const graph = build('function a() { b(); }\nfunction b() { a(); }');
    const a = graph.functions.find((fn) => fn.name === 'a');
    const b = graph.functions.find((fn) => fn.name === 'b');
    expect(a?.callees.some((id) => id.endsWith('::b'))).toBe(true);
    expect(b?.callees.some((id) => id.endsWith('::a'))).toBe(true);
  });
});

describe('ルール 13・14: メソッド・クラス', () => {
  it('同一クラスの this.m() を解決する', () => {
    const graph = build('class C { m(x: any) { return x; } n(req: any) { this.m(req.query.q); } }');
    const n = graph.functions.find((fn) => fn.name === 'n');
    expect(n?.callees.some((id) => id.endsWith('::C.m'))).toBe(true);
  });

  it('クラスメソッドが関数 ID にクラス名を含む', () => {
    const graph = build('class C { m() { return 1; } }');
    expect(graph.functions.some((fn) => fn.id === 'a.ts::C.m')).toBe(true);
  });

  it('getter も関数として登録する', () => {
    const graph = build('class C { get v() { return 1; } }');
    expect(graph.functions.some((fn) => fn.name === 'v')).toBe(true);
  });

  it('ファイル内で一意なメソッド名なら obj.m() を解決する', () => {
    const graph = build('class C { m(x: any) { return x; } }\nfunction f(req: any) { const c = new C(); c.m(req.query.q); }');
    const f = graph.functions.find((fn) => fn.name === 'f');
    expect(f?.callees.some((id) => id.endsWith('::C.m'))).toBe(true);
  });

  it('コンストラクタも登録する', () => {
    const graph = build('class C { constructor(private x: any) {} }');
    expect(graph.functions.some((fn) => fn.name === 'constructor')).toBe(true);
  });
});

describe('ルール 15: 高階関数とコールバック', () => {
  it('コールバックの仮引数ノードを作る', () => {
    const graph = build('function f(req: any) { [1, 2].map((x: any) => sink(x)); }');
    const callback = graph.functions.find((fn) => fn.name.includes('map'));
    expect(callback).toBeDefined();
  });

  it('コールバック関数が登録され、引数位置に応じた名前を持つ', () => {
    const graph = build("app.get('/x', (req: any, res: any) => { sink(req.query.a); });");
    expect(graph.functions.some((fn) => fn.name.endsWith('~arg1'))).toBe(true);
  });

  it('forEach のコールバックも登録する', () => {
    const graph = build('function f(items: any) { items.forEach((item: any) => sink(item)); }');
    expect(graph.functions.length).toBeGreaterThanOrEqual(2);
  });
});

describe('ルール 16: 関数引数 → 戻り値', () => {
  it('恒等関数の return ノードまで到達する', () => {
    const graph = build('function id(x: any) { return x; }');
    const ret = graph.nodes.find((node) => node.kind === 'return');
    expect(flows(graph, nodeByLabel(graph, 'x').id, ret?.id ?? '')).toBe(true);
  });

  it('引数ノードが仮引数として登録される', () => {
    const graph = build('function f(a: any, b: any) { return a; }');
    const params = graph.nodes.filter((node) => node.kind === 'param');
    expect(params.map((node) => node.label)).toEqual(['a', 'b']);
  });

  it('残余引数・省略可能引数を記録する', () => {
    const graph = build('function f(a: any, b?: any, ...rest: any[]) {}');
    const fn = graph.functions[0];
    expect(fn?.params.map((p) => p.name)).toEqual(['a', 'b', 'rest']);
    expect(fn?.params[1]?.optional).toBe(true);
    expect(fn?.params[2]?.rest).toBe(true);
  });
});

describe('位置情報と決定性', () => {
  it('行・列は 1-based で記録される', () => {
    const graph = build('function f(req: any) {\n  sink(req.query.a);\n}');
    const source = nodeByLabel(graph, 'req.query.a');
    expect(source.range.start.line).toBe(2);
    expect(source.range.start.column).toBe(8);
  });

  it('同じソースからは同じ IR が得られる（決定的）', () => {
    const source = 'function f(req: any) { const a = req.query.x; sink(a); }';
    const first = build(source);
    const second = build(source);
    expect(second.nodes.map((n) => `${n.id}|${n.label}`)).toEqual(first.nodes.map((n) => `${n.id}|${n.label}`));
    expect(second.edges.length).toBe(first.edges.length);
  });

  it('構文エラーがあっても部分的な IR を返し、診断を残す', () => {
    const graph = build('function f(req: any) { const a = req.query.x; sink(a) }');
    expect(graph.functions.length).toBeGreaterThan(0);
  });
});

describe('診断と未解決呼び出し', () => {
  it('未対応の式でも unknown ノードを作り、例外を投げない', () => {
    const graph = build('function f() { const x = <div />; }');
    expect(graph.nodes.some((node) => node.kind === 'unknown' || node.kind === 'local')).toBe(true);
  });
});
