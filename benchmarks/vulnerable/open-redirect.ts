import express from 'express';

const app = express();

app.get('/go', (req, res) => {
  const next = req.query.next;
  res.redirect(next);
});
