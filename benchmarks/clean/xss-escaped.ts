import express from 'express';
import escapeHtml from 'escape-html';

const app = express();

app.get('/comment', (req, res) => {
  const comment = req.query.comment;
  const safe = escapeHtml(comment);
  const node = document.getElementById('comment');
  node.innerHTML = '<p>' + safe + '</p>';
  res.end();
});
