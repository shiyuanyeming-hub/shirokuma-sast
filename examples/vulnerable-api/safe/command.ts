import express from 'express';
import { execFile } from 'child_process';

const app = express();

// 配列引数（constant-argument 検証つき）。
app.get('/ping', (req, res) => {
  const host = req.query.host;
  execFile('ping', ['-c', '1', host], (error, stdout) => res.send(stdout));
});

export { app };
