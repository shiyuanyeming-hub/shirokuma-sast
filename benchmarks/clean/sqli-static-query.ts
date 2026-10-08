import express from 'express';

const app = express();

app.get('/health', (req, res) => {
  db.query('SELECT 1', (err, rows) => res.json(rows));
});
