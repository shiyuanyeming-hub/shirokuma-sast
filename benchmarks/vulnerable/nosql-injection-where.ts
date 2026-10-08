import express from 'express';

const app = express();

app.post('/reports', async (req, res) => {
  const clause = req.body.clause;
  const rows = await Report.$where(clause);
  res.json(rows);
});
