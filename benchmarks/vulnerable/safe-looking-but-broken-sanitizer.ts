import express from 'express';

const app = express();

// エスケープした「つもり」で文字列連結している例。
// エスケープは SQL のメタ文字（引用符・バックスラッシュ）を無害化しないため、
// 汚染は残ったままシンクへ到達する。
function escapeHtmlLike(input: string): string {
  return input.replace(/&/g, '&amp;').replace(/</g, '&lt;');
}

app.get('/notes', (req, res) => {
  const note = req.query.note;
  const escaped = escapeHtmlLike(note);
  const sql = "SELECT * FROM notes WHERE body = '" + escaped + "'";
  db.query(sql, (err, rows) => res.json(rows));
});
