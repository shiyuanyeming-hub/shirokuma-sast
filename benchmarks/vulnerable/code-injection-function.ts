import express from 'express';

const app = express();

app.get('/run', (req, res) => {
  const body = req.body.code;
  const fn = new Function('return ' + body);
  res.json({ result: fn() });
});
