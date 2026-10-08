import express from 'express';

const app = express();

app.get('/ad', (req, res) => {
  const banner = req.query.banner;
  document.write(banner);
  res.end();
});
