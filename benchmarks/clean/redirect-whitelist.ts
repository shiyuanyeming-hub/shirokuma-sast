import express from 'express';

const ALLOWED = new Set(['/home', '/settings', '/profile']);

const app = express();

app.get('/go', (req, res) => {
  const requested = String(req.query.next);
  const target = ALLOWED.has(requested) ? requested : '/home';
  res.redirect(target);
});
