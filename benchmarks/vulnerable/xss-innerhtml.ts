import express from 'express';

const app = express();

app.get('/profile', (req, res) => {
  const nickname = req.query.nickname;
  const node = document.getElementById('profile');
  node.innerHTML = '<h1>' + nickname + '</h1>';
  res.end();
});
