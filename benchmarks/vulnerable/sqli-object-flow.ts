import express from 'express';

const app = express();

app.post('/login', (req, res) => {
  const credentials = { name: req.body.username, pass: req.body.password };
  const sql = "SELECT * FROM accounts WHERE name = '" + credentials.name + "' AND pass = '" + credentials.pass + "'";
  db.query(sql, (err, rows) => res.json(rows));
});
