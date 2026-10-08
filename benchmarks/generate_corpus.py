"""ベンチマーク用のソースファイルを生成する（開発時の一括作成用）。"""
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
V = ROOT / 'benchmarks' / 'vulnerable'
C = ROOT / 'benchmarks' / 'clean'
V.mkdir(parents=True, exist_ok=True)
C.mkdir(parents=True, exist_ok=True)

VULNERABLE = {
    'sqli-concat.ts': '''import express from 'express';

const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  db.query(sql, (err, rows) => res.json(rows));
});
''',
    'sqli-template.ts': '''import express from 'express';

const app = express();

app.get('/search', (req, res) => {
  const term = req.query.q;
  const sql = `SELECT * FROM items WHERE name LIKE '%${term}%'`;
  db.query(sql, (err, rows) => res.json(rows));
});
''',
    'sqli-interprocedural.ts': '''import express from 'express';

const app = express();

function buildQuery(raw: string): string {
  const suffix = ' ORDER BY created_at DESC';
  return 'SELECT * FROM orders WHERE customer = "' + raw + '"' + suffix;
}

app.get('/orders', (req, res) => {
  const customer = req.query.customer;
  const sql = buildQuery(customer);
  db.query(sql, (err, rows) => res.json(rows));
});
''',
    'sqli-object-flow.ts': '''import express from 'express';

const app = express();

app.post('/login', (req, res) => {
  const credentials = { name: req.body.username, pass: req.body.password };
  const sql = "SELECT * FROM accounts WHERE name = '" + credentials.name + "' AND pass = '" + credentials.pass + "'";
  db.query(sql, (err, rows) => res.json(rows));
});
''',
    'xss-innerhtml.ts': '''import express from 'express';

const app = express();

app.get('/profile', (req, res) => {
  const nickname = req.query.nickname;
  const node = document.getElementById('profile');
  node.innerHTML = '<h1>' + nickname + '</h1>';
  res.end();
});
''',
    'xss-template.ts': '''import express from 'express';

const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name;
  const html = `<div class="card">${name}</div>`;
  res.send(html);
});
''',
    'xss-document-write.ts': '''import express from 'express';

const app = express();

app.get('/ad', (req, res) => {
  const banner = req.query.banner;
  document.write(banner);
  res.end();
});
''',
    'cwe78-exec-concat.ts': '''import express from 'express';
import { exec } from 'child_process';

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (error, stdout) => {
    res.send(stdout);
  });
});
''',
    'cwe78-exec-template.ts': '''import express from 'express';
import child_process from 'child_process';

const app = express();

app.get('/convert', (req, res) => {
  const file = req.query.file;
  child_process.exec(`ffmpeg -i ${file} out.mp4`, (error, stdout) => {
    res.send(stdout);
  });
});
''',
    'cwe78-exec-interprocedural.ts': '''import express from 'express';
import { execSync } from 'child_process';

const app = express();

function toCommand(target: string): string {
  return 'nslookup ' + target;
}

app.get('/dns', (req, res) => {
  const domain = req.query.domain;
  const output = execSync(toCommand(domain));
  res.send(output);
});
''',
    'path-traversal-readfile.ts': '''import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
  const name = req.query.name;
  const target = path.join('/srv/files', name);
  const contents = fs.readFileSync(target, 'utf8');
  res.send(contents);
});
''',
    'path-traversal-sendfile.ts': '''import express from 'express';

const app = express();

app.get('/asset', (req, res) => {
  const asset = req.query.asset;
  res.sendFile('/var/www/assets/' + asset);
});
''',
    'code-injection-eval.ts': '''import express from 'express';

const app = express();

app.get('/calc', (req, res) => {
  const expression = req.query.expression;
  const value = eval(expression);
  res.json({ value });
});
''',
    'code-injection-function.ts': '''import express from 'express';

const app = express();

app.get('/run', (req, res) => {
  const body = req.body.code;
  const fn = new Function('return ' + body);
  res.json({ result: fn() });
});
''',
    'nosql-injection-find.ts': '''import express from 'express';

const app = express();

app.post('/lookup', async (req, res) => {
  const filter = req.body.filter;
  const rows = await User.find(filter);
  res.json(rows);
});
''',
    'nosql-injection-where.ts': '''import express from 'express';

const app = express();

app.post('/reports', async (req, res) => {
  const clause = req.body.clause;
  const rows = await Report.$where(clause);
  res.json(rows);
});
''',
    'open-redirect.ts': '''import express from 'express';

const app = express();

app.get('/go', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});
''',
    'ssrf-fetch.ts': '''import express from 'express';
import axios from 'axios';

const app = express();

app.get('/proxy', async (req, res) => {
  const endpoint = req.query.url;
  const response = await axios.get(endpoint);
  res.json(response.data);
});
''',
    'safe-looking-but-broken-sanitizer.ts': '''import express from 'express';

const app = express();

// エスケープした「つもり」で文字列連結している例。
// エスケープは SQL のメタ文字（引用符・バックスラッシュ）を無害化しないため、
// 汚染は残ったままシンクへ到達する。
function escapeHtmlLike(input: string): string {
  return input.replace(/&/g, '&amp;').replace(/</g, '&lt;');
}

app.get('/notes', (req, res) => {
  const note = req.query.note;
  const escaped = escapeHtmlLike(note);
  const sql = "SELECT * FROM notes WHERE body = '" + escaped + "'";
  db.query(sql, (err, rows) => res.json(rows));
});
''',
}

CLEAN = {
    'sqli-parameterized.ts': '''import express from 'express';

const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = $1', [id], (err, rows) => res.json(rows));
});
''',
    'sqli-static-query.ts': '''import express from 'express';

const app = express();

app.get('/health', (req, res) => {
  db.query('SELECT 1', (err, rows) => res.json(rows));
});
''',
    'sqli-safe-helper.ts': '''import express from 'express';

const app = express();

function lookupUser(id: string): unknown {
  // プレースホルダを使うヘルパーは安全。呼び出し元の汚染をシンクへ流さない。
  return db.query('SELECT * FROM users WHERE id = $1', [id]);
}

app.get('/user', (req, res) => {
  const id = req.query.id;
  res.json(lookupUser(id));
});
''',
    'xss-escaped.ts': '''import express from 'express';
import escapeHtml from 'escape-html';

const app = express();

app.get('/comment', (req, res) => {
  const comment = req.query.comment;
  const safe = escapeHtml(comment);
  const node = document.getElementById('comment');
  node.innerHTML = '<p>' + safe + '</p>';
  res.end();
});
''',
    'xss-double-escaped.ts': '''import express from 'express';
import escapeHtml from 'escape-html';

const app = express();

app.get('/widget', (req, res) => {
  const label = escapeHtml(escapeHtml(req.query.label));
  res.send('<span>' + label + '</span>');
});
''',
    'cwe78-execfile-array.ts': '''import express from 'express';
import { execFile } from 'child_process';

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // 配列引数の execFile はシェルを経由しないため、コマンド注入にはならない。
  execFile('ping', ['-c', '1', host], (error, stdout) => {
    res.send(stdout);
  });
});
''',
    'path-static-file.ts': '''import express from 'express';
import fs from 'fs';

const app = express();

app.get('/readme', (req, res) => {
  const contents = fs.readFileSync('/srv/files/README.md', 'utf8');
  res.send(contents);
});
''',
    'path-basename.ts': '''import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
  const safeName = path.basename(req.query.name as string);
  const contents = fs.readFileSync(path.join('/srv/files', safeName), 'utf8');
  res.send(contents);
});
''',
    'nosql-validated-number.ts': '''import express from 'express';

const app = express();

app.post('/lookup', async (req, res) => {
  const raw = req.body.userId;
  const userId = Number.parseInt(String(raw), 10);
  const rows = await User.find({ id: userId });
  res.json(rows);
});
''',
    'redirect-whitelist.ts': '''import express from 'express';

const ALLOWED = new Set(['/home', '/settings', '/profile']);

const app = express();

app.get('/go', (req, res) => {
  const requested = String(req.query.next);
  const target = ALLOWED.has(requested) ? requested : '/home';
  res.redirect(target);
});
''',
    'ssrf-allowlist-host.ts': '''import express from 'express';
import axios from 'axios';

const ALLOWED_HOST = 'api.internal.example';

const app = express();

app.get('/proxy', async (req, res) => {
  const endpoint = `${'https://' + ALLOWED_HOST}/v1/items`;
  const response = await axios.get(endpoint);
  res.json(response.data);
});
''',
    'taint-without-sink.ts': '''import express from 'express';

const app = express();

// 汚染は流れるが、危険なシンクへ到達しないため検出してはいけない。
app.get('/echo', (req, res) => {
  const label = req.query.label;
  const upper = String(label).toUpperCase();
  res.json({ label: upper });
});
''',
}

for name, body in VULNERABLE.items():
    (V / name).write_text(body, encoding='utf-8')
for name, body in CLEAN.items():
    (C / name).write_text(body, encoding='utf-8')

print(f'vulnerable: {len(VULNERABLE)} files')
print(f'clean: {len(CLEAN)} files')
