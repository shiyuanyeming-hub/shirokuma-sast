import express from 'express';
import child_process from 'child_process';

const app = express();

app.get('/convert', (req, res) => {
  const file = req.query.file;
  child_process.exec(`ffmpeg -i ${file} out.mp4`, (error, stdout) => {
    res.send(stdout);
  });
});
