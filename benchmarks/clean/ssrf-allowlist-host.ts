import express from 'express';
import axios from 'axios';

const ALLOWED_HOST = 'api.internal.example';

const app = express();

app.get('/proxy', async (req, res) => {
  const endpoint = `${'https://' + ALLOWED_HOST}/v1/items`;
  const response = await axios.get(endpoint);
  res.json(response.data);
});
