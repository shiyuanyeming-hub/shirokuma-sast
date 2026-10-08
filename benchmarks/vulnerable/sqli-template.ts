import express from 'express';

const app = express();

app.get('/search', (req, res) => {
  const term = req.query.q;
  const sql = `SELECT * FROM items WHERE name LIKE '%${term}%'`;
  db.query(sql, (err, rows) => res.json(rows));
});
