import express from 'express';
import escapeHtml from 'escape-html';

const app = express();

app.get('/widget', (req, res) => {
  const label = escapeHtml(escapeHtml(req.query.label));
  res.send('<span>' + label + '</span>');
});
