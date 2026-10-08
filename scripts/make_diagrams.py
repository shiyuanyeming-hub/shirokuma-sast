"""README 用の図を生成する。

文字幅を推測するとレイアウトが崩れるため、Pillow で実際に測ってから
SVG を組み立てる。生成物は docs/assets/ に置き、PNG へ変換して README から参照する。

使い方:
    python3 scripts/make_diagrams.py
    rsvg-convert -z 2 docs/assets/taint-flow.svg -o docs/assets/taint-flow.png
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

from PIL import ImageFont

ROOT = pathlib.Path(__file__).resolve().parents[1]
ASSETS = ROOT / "docs" / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

# 日本語はヒラギノ、コードは Menlo。どちらも macOS 標準。
JP_FONT = "/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc"
JP_BOLD = "/System/Library/Fonts/ヒラギノ角ゴシック W6.ttc"
MONO_FONT = "/System/Library/Fonts/Menlo.ttc"

_cache: dict[tuple[str, int], ImageFont.FreeTypeFont] = {}


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    key = (path, size)
    if key not in _cache:
        _cache[key] = ImageFont.truetype(path, size)
    return _cache[key]


def text_width(text: str, path: str, size: int) -> float:
    """文字列の描画幅を実測する。"""
    return font(path, size).getlength(text)


def esc(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass
class Colors:
    bg: str = "#ffffff"
    panel: str = "#f6f8fa"
    border: str = "#d0d7de"
    text: str = "#1f2328"
    muted: str = "#59636e"
    code_bg: str = "#f6f8fa"
    source: str = "#bc4c00"
    source_bg: str = "#fff1e5"
    prop: str = "#0969da"
    prop_bg: str = "#ddf4ff"
    sanitize: str = "#1a7f37"
    sanitize_bg: str = "#dafbe1"
    sink: str = "#cf222e"
    sink_bg: str = "#ffebe9"
    arrow: str = "#59636e"


C = Colors()


def build_taint_flow_svg() -> str:
    """汚染が source から sink へ流れる様子を示す図。

    描画は 2 パスに分ける。先に背景・ハイライト・バッジを描き、
    そのあと文字をまとめて描く。逆順にすると、ハイライトが文字を覆い隠す。
    """
    margin = 28
    panel_top = 44
    code_size = 15
    label_size = 13
    h_size = 20
    line_height = 26

    code_lines: list[tuple[str, str | None]] = [
        ("const express = require('express');", None),
        ("", None),
        ("const app = express();", None),
        ("", None),
        ("app.get('/users', (req, res) => {", None),
        ("  const id = req.query.id;", "source"),
        ("  const sql = 'SELECT * FROM users WHERE id = ' + id;", "propagate"),
        ("  db.query(sql);", "sink"),
        ("});", None),
    ]

    # --- 幅を実測して決める ---
    line_no_w = text_width("99", MONO_FONT, code_size) + 6
    longest = max(text_width(t, MONO_FONT, code_size) for t, _ in code_lines)
    gutter = 12
    badge_w = max(text_width(r, MONO_FONT, label_size - 2) for r in ("source", "propagate", "sink")) + 18
    code_x = margin + 16 + line_no_w + gutter          # コード文字列の左端
    code_right = code_x + longest
    code_panel_w = code_right - margin + badge_w + 34

    code_top = panel_top + 52
    code_panel_h = code_top - panel_top + line_height * len(code_lines) + 6

    # --- 右パネル ---
    result_x = margin + code_panel_w + 40
    width = 1240
    result_w = width - result_x - margin

    proof_rows: list[tuple[str, str, str, str]] = [
        ("source", "6:15", "req.query.id", "クエリ文字列が入口"),
        ("propagate", "6:9", "id", "変数へ代入"),
        ("propagate", "7:22", "'SELECT …' + id", "文字列連結"),
        ("propagate", "7:9", "sql", "変数へ代入"),
        ("sink", "8:3", "db.query", "SQL 実行"),
    ]
    proof_size = 13
    role_col = 92
    loc_col = 52
    # 最長ラベル + 余白。実測値だけだと長い式で注記欄へはみ出すため余裕を持たせる。
    label_col = max(text_width(r[2], MONO_FONT, proof_size) for r in proof_rows) + 60
    note_col = proof_size + role_col + loc_col + label_col
    proof_top = panel_top + 124
    proof_lh = 30

    panel_h = max(code_panel_h, proof_top - panel_top + proof_lh * len(proof_rows) + 26)
    height = panel_top + panel_h + 62

    bg: list[str] = []
    fg: list[str] = []

    # ------------------------------------------------------------------
    # 背景パス
    # ------------------------------------------------------------------
    bg.append(f'<rect width="100%" height="100%" fill="{C.bg}"/>')
    bg.append(
        f'<rect x="{margin}" y="{panel_top}" width="{code_panel_w}" height="{panel_h}" rx="10" '
        f'fill="{C.panel}" stroke="{C.border}"/>'
    )
    bg.append(
        f'<rect x="{result_x}" y="{panel_top}" width="{result_w}" height="{panel_h}" rx="10" '
        f'fill="{C.panel}" stroke="{C.border}"/>'
    )

    # 行のハイライトと役割バッジ
    for index, (text, role) in enumerate(code_lines):
        if role is None:
            continue
        y = code_top + index * line_height
        highlight = {"source": C.source_bg, "propagate": C.prop_bg, "sink": C.sink_bg}[role]
        bg.append(
            f'<rect x="{margin + 8}" y="{y - code_size - 4}" width="{code_panel_w - 16}" '
            f'height="{line_height - 6}" rx="5" fill="{highlight}" opacity="0.9"/>'
        )
        color = {"source": C.source, "propagate": C.prop, "sink": C.sink}[role]
        badge_x = margin + code_panel_w - 16 - badge_w
        bg.append(
            f'<rect x="{badge_x}" y="{y - code_size - 2}" width="{badge_w}" height="{line_height - 10}" '
            f'rx="9" fill="{color}" opacity="0.15"/>'
        )

    # 経路ツリーの縦ガイド。最後の行までしか引かない（柵に見えないように）。
    for index in range(len(proof_rows) - 1):
        y = proof_top + index * proof_lh
        bg.append(
            f'<line x1="{result_x + 34}" y1="{y + 3}" x2="{result_x + 34}" y2="{y + proof_lh}" '
            f'stroke="{C.border}" stroke-width="1.5"/>'
        )

    # ------------------------------------------------------------------
    # 文字パス
    # ------------------------------------------------------------------
    title = "汚染はどこから来て、どこへ届くのか"
    fg.append(
        f'<text x="{margin}" y="34" font-size="{h_size}" font-weight="600" fill="{C.text}">{esc(title)}</text>'
    )
    fg.append(
        f'<text x="{margin + text_width(title, JP_BOLD, h_size) + 14}" y="34" font-size="{label_size + 1}" '
        f'fill="{C.muted}">— 変数と文字列連結を経由しても追跡できる</text>'
    )

    fg.append(
        f'<text x="{margin + 16}" y="{panel_top + 30}" font-size="{label_size + 1}" font-weight="600" '
        f'fill="{C.text}">src/app.ts</text>'
    )

    for index, (text, role) in enumerate(code_lines):
        y = code_top + index * line_height
        fg.append(
            f'<text x="{margin + 16 + line_no_w}" y="{y}" font-size="{code_size}" fill="{C.muted}" '
            f'font-family="Menlo, monospace" text-anchor="end">{index + 1}</text>'
        )
        if text == "":
            continue
        fill = {"source": C.source, "propagate": C.prop, "sink": C.sink}.get(role or "", C.text)
        fg.append(
            f'<text x="{code_x}" y="{y}" font-size="{code_size}" fill="{fill}" '
            f'font-family="Menlo, monospace" xml:space="preserve">{esc(text)}</text>'
        )
        if role is not None:
            color = {"source": C.source, "propagate": C.prop, "sink": C.sink}[role]
            badge_x = margin + code_panel_w - 16 - badge_w
            fg.append(
                f'<text x="{badge_x + badge_w / 2}" y="{y - 3}" font-size="{label_size - 2}" '
                f'font-family="Menlo, monospace" fill="{color}" text-anchor="middle">{role}</text>'
            )

    fg.append(
        f'<text x="{result_x + 18}" y="{panel_top + 30}" font-size="{label_size + 1}" font-weight="600" '
        f'fill="{C.text}">shirokuma-sast — 検出 1 件</text>'
    )
    fg.append(
        f'<text x="{result_x + 18}" y="{panel_top + 60}" font-size="{label_size + 2}" font-weight="600" '
        f'font-family="Menlo, monospace" fill="{C.sink}">[error] sql-query  src/app.ts:8:3</text>'
    )
    fg.append(
        f'<text x="{result_x + 18}" y="{panel_top + 86}" font-size="{label_size}" fill="{C.text}">'
        f'`query()` へ未エスケープの外部入力が到達しています（SQL インジェクション）</text>'
    )
    fg.append(
        f'<text x="{result_x + 18}" y="{panel_top + 106}" font-size="{label_size}" fill="{C.muted}">'
        f'cwe: CWE-89  ·  経路の各ステップがそのまま出力される</text>'
    )

    for index, (role, location, label, note) in enumerate(proof_rows):
        y = proof_top + index * proof_lh
        is_last = index == len(proof_rows) - 1
        connector = "└─" if is_last else "├─"
        color = {"source": C.source, "propagate": C.prop, "sanitize": C.sanitize, "sink": C.sink}[role]
        fg.append(
            f'<text x="{result_x + 20}" y="{y}" font-size="{proof_size}" font-family="Menlo, monospace" '
            f'fill="{C.muted}">{connector}</text>'
        )
        fg.append(
            f'<text x="{result_x + 48}" y="{y}" font-size="{proof_size}" font-family="Menlo, monospace" '
            f'fill="{color}" font-weight="600">{role}</text>'
        )
        fg.append(
            f'<text x="{result_x + 48 + role_col}" y="{y}" font-size="{proof_size}" '
            f'font-family="Menlo, monospace" fill="{C.muted}">{esc(location)}</text>'
        )
        fg.append(
            f'<text x="{result_x + 48 + role_col + loc_col}" y="{y}" font-size="{proof_size}" '
            f'font-family="Menlo, monospace" fill="{C.text}" xml:space="preserve">{esc(label)}</text>'
        )
        fg.append(
            f'<text x="{result_x + 48 + note_col}" y="{y}" font-size="{proof_size}" fill="{C.muted}">'
            f'{esc(note)}</text>'
        )

    footnote = (
        "正規表現で関数名を探すだけでは、変数を経由した汚染は追えない。"
        "データフローグラフに落とすことで、5 ホップ先のシンクまで根拠付きで示せる。"
    )
    fg.append(
        f'<text x="{margin}" y="{panel_top + panel_h + 34}" font-size="{label_size}" fill="{C.muted}">'
        f'{esc(footnote)}</text>'
    )

    return "\n".join(
        [
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" '
            f'font-family="Hiragino Sans, Hiragino Kaku Gothic Pro, sans-serif">',
            *bg,
            *fg,
            "</svg>",
        ]
    )


def write(name: str, svg: str) -> None:
    target = ASSETS / f"{name}.svg"
    target.write_text(svg, encoding="utf-8")
    print(f"wrote {target.relative_to(ROOT)} ({len(svg)} bytes)")


if __name__ == "__main__":
    write("taint-flow", build_taint_flow_svg())
