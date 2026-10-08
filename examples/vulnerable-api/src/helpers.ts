import express from 'express';

const app = express();

// 汚染はヘルパーの引数として入り、戻り値として出て、呼び出し元のシンクへ届く。
// 単一ファイル内の構文だけを見る実装では追えない形。
function buildQuery(customer: string): string {
  const suffix = ' ORDER BY created_at DESC';
  return 'SELECT * FROM orders WHERE customer = "' + customer + '"' + suffix;
}

app.get('/orders', (req, res) => {
  const sql = buildQuery(req.query.customer);
  db.query(sql, (err, rows) => res.json(rows));
});

export { app };
