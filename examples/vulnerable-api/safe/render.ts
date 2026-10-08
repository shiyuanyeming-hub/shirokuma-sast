import express from 'express';
import escapeHtml from 'escape-html';

const app = express();

// エスケープを通すと html タグが落ちるため、innerHTML へ入れても検出されない。
app.get('/comment', (req, res) => {
  const comment = req.query.comment;
  const safe = escapeHtml(comment);
  const node = document.getElementById('comment');
  node.innerHTML = '<p>' + safe + '</p>';
  res.end();
});

export { app };
