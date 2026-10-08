import express from 'express';
import { execFile } from 'child_process';

const app = express();

app.get('/ping', (req, res) => {
  const host = req.query.host;
  // 配列引数の execFile はシェルを経由しないため、コマンド注入にはならない。
  execFile('ping', ['-c', '1', host], (error, stdout) => {
    res.send(stdout);
  });
});
