import express from 'express';

const app = express();

function lookupUser(id: string): unknown {
  // プレースホルダを使うヘルパーは安全。呼び出し元の汚染をシンクへ流さない。
  return db.query('SELECT * FROM users WHERE id = $1', [id]);
}

app.get('/user', (req, res) => {
  const id = req.query.id;
  res.json(lookupUser(id));
});
