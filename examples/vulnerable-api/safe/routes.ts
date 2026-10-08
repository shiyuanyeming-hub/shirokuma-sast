import express from 'express';

const app = express();

// プレースホルダを使う正しい形。
// `db.query` はサニタイザでもあり、第 1 引数がリテラルなら sql タグを落とす。
app.get('/users', (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM users WHERE id = $1', [id], (err, rows) => res.json(rows));
});

export { app };
