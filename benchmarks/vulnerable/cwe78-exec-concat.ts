import express from 'express';
import { exec } from 'child_process';

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (error, stdout) => {
    res.send(stdout);
  });
});
