import express from 'express';

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
