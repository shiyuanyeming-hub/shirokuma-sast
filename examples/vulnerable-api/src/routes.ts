import express from 'express';

const app = express();

app.get('/users', (req, res) => {
  const id = req.query.id;
  const sql = 'SELECT * FROM users WHERE id = ' + id;
  db.query(sql, (err, rows) => res.json(rows));
});

export { app };
