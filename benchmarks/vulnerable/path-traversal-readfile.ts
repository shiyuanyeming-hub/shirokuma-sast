import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
  const name = req.query.name;
  const target = path.join('/srv/files', name);
  const contents = fs.readFileSync(target, 'utf8');
  res.send(contents);
});
