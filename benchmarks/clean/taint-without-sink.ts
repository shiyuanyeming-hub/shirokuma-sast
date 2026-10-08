import express from 'express';

const app = express();

// 汚染は流れるが、危険なシンクへ到達しないため検出してはいけない。
app.get('/echo', (req, res) => {
  const label = req.query.label;
  const upper = String(label).toUpperCase();
  res.json({ label: upper });
});
