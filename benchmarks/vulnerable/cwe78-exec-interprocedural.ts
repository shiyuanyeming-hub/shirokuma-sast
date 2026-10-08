import express from 'express';
import { execSync } from 'child_process';

const app = express();

function toCommand(target: string): string {
  return 'nslookup ' + target;
}

app.get('/dns', (req, res) => {
  const domain = req.query.domain;
  const output = execSync(toCommand(domain));
  res.send(output);
});
