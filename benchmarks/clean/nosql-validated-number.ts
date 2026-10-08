import express from 'express';

const app = express();

app.post('/lookup', async (req, res) => {
  const raw = req.body.userId;
  const userId = Number.parseInt(String(raw), 10);
  const rows = await User.find({ id: userId });
  res.json(rows);
});
