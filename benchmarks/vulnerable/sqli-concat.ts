import express from 'express';

const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  db.query(sql, (err, rows) => res.json(rows));
});
