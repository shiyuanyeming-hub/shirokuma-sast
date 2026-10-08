import express from 'express';

const app = express();

app.get('/asset', (req, res) => {
  const asset = req.query.asset;
  res.sendFile('/var/www/assets/' + asset);
});
