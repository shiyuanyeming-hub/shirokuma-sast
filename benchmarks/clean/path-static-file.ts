import express from 'express';
import fs from 'fs';

const app = express();

app.get('/readme', (req, res) => {
  const contents = fs.readFileSync('/srv/files/README.md', 'utf8');
  res.send(contents);
});
