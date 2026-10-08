import express from 'express';
import { exec, execFile } from 'child_process';

const app = express();

// 1) exec + 文字列連結 → 検出される
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (error, stdout) => res.send(stdout));
});

// 2) 同じ汚染でも execFile に配列を渡すと検出されない。
//    シェルを経由しないため、引数が解釈されない。
app.get('/ping-safe', (req, res) => {
  const host = req.query.host;
  execFile('ping', ['-c', '1', host], (error, stdout) => res.send(stdout));
});

export { app };
