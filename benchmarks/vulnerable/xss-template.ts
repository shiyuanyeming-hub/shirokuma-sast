import express from 'express';

const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name;
  const html = `<div class="card">${name}</div>`;
  res.send(html);
});
