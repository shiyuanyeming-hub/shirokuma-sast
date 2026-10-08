import express from 'express';

const app = express();

app.get('/calc', (req, res) => {
  const expression = req.query.expression;
  const value = eval(expression);
  res.json({ value });
});
