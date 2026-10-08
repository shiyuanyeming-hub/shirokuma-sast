import express from 'express';

const app = express();

app.post('/lookup', async (req, res) => {
  const filter = req.body.filter;
  const rows = await User.find(filter);
  res.json(rows);
});
