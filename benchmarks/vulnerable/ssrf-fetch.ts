import express from 'express';
import axios from 'axios';

const app = express();

app.get('/proxy', async (req, res) => {
  const endpoint = req.query.url;
  const response = await axios.get(endpoint);
  res.json(response.data);
});
