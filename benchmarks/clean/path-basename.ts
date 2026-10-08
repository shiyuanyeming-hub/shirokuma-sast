import express from 'express';
import fs from 'fs';
import path from 'path';

const app = express();

app.get('/download', (req, res) => {
  const safeName = path.basename(req.query.name as string);
  const contents = fs.readFileSync(path.join('/srv/files', safeName), 'utf8');
  res.send(contents);
});
