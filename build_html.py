#!/usr/bin/env python3
"""
build_html.py — PORTFOLIO_reversing_challenge.md -> 단일 HTML

fw_work/build_html.sh 와 같은 방식이다.
  - python-markdown 으로 본문 변환
  - 이미지를 base64 data URI 로 파일 안에 내장 (단일 파일로 배포/인쇄 가능)
  - CSS 는 이 스크립트가 주입 (md 에는 스타일이 없다)

추가된 동작:
  - img/ 에 파일이 아직 없으면 점선 자리표시 박스로 렌더링한다.
    스크린샷을 img/ 에 넣고 다시 실행하면 자동으로 그 자리에 들어간다.
  - ![alt](src) 의 alt 텍스트가 그림 캡션이 된다.
  - <div class="two" markdown="1"> 로 감싼 이미지 2장은 좌우 2단으로 배치된다.

사용:
    python build_html.py
"""

import base64
import html as ihtml
import mimetypes
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MD = os.path.join(HERE, "PORTFOLIO_reversing_challenge.md")
OUT = os.path.join(HERE, "PORTFOLIO_reversing_challenge.html")
IMGDIR = os.path.join(HERE, "img")

try:
    import markdown
except ImportError:
    print("[*] python-markdown 설치 중...")
    subprocess.run([sys.executable, "-m", "pip", "install", "markdown", "-q"], check=True)
    import markdown


# ── 본문 변환 ────────────────────────────────────────────────────────────
md_text = open(MD, encoding="utf-8").read()
html_body = markdown.markdown(
    md_text,
    extensions=["tables", "fenced_code", "sane_lists", "md_in_html", "attr_list"],
)

missing = []
embedded = []

IMG_RE = re.compile(r'<img\s+([^>]*?)/?>', re.I)
ATTR_RE = re.compile(r'(\w+)\s*=\s*"([^"]*)"')


def render_image(tag_attrs):
    """<img> 한 개를 <figure> 또는 자리표시 박스로 바꾼다."""
    attrs = dict(ATTR_RE.findall(tag_attrs))
    src = attrs.get("src", "")
    alt = attrs.get("alt", "")

    if src.startswith("data:") or src.startswith("http"):
        return f'<figure><img src="{src}" alt="{ihtml.escape(alt)}">' \
               f'<figcaption>{ihtml.escape(alt)}</figcaption></figure>'

    path = os.path.join(HERE, src.replace("/", os.sep))

    if os.path.exists(path):
        embedded.append(src)
        # SVG 는 base64 로 감싸지 않고 그대로 펼친다.
        # <img> 안의 SVG 는 별도 문서가 되어 currentColor 가 본문 색을 따라가지 못한다.
        if path.lower().endswith(".svg"):
            svg = open(path, encoding="utf-8").read()
            svg = re.sub(r"<\?xml.*?\?>", "", svg, flags=re.S).strip()
            return (f'<figure class="svgfig">{svg}'
                    f'<figcaption>{ihtml.escape(alt)}</figcaption></figure>')

        mime = mimetypes.guess_type(path)[0] or "image/png"
        b64 = base64.b64encode(open(path, "rb").read()).decode()
        return (f'<figure><img src="data:{mime};base64,{b64}" alt="{ihtml.escape(alt)}">'
                f'<figcaption>{ihtml.escape(alt)}</figcaption></figure>')

    # 아직 없는 이미지 -> 자리표시 박스
    missing.append(src)
    return (
        '<figure><div class="ph">'
        '<div class="tag">[ 이미지 자리 ]</div>'
        f'<div class="what">{ihtml.escape(alt)}</div>'
        f'<div class="file">{ihtml.escape(src)}</div>'
        '</div></figure>'
    )


# 변환 결과를 토큰으로 치환해 두고 마지막에 복원한다.
# 그러지 않으면 2차 패스가 1차 패스에서 만든 <img> 를 다시 매칭해
# <figure> 가 이중으로 감싸지고 캡션이 두 번 나온다.
slots = []


def stash(fragment):
    slots.append(fragment)
    return "\x00FIG%d\x00" % (len(slots) - 1)


# <p><img ...></p> 형태를 먼저 처리 (markdown 이 단독 이미지를 p 로 감싼다)
html_body = re.sub(
    r'<p>\s*<img\s+([^>]*?)/?>\s*</p>',
    lambda m: stash(render_image(m.group(1))),
    html_body,
    flags=re.I,
)
# 남은 <img> (표 안 등)
html_body = IMG_RE.sub(lambda m: stash(render_image(m.group(1))), html_body)

html_body = re.sub(r"\x00FIG(\d+)\x00", lambda m: slots[int(m.group(1))], html_body)


# ── CSS ─────────────────────────────────────────────────────────────────
CSS = """
:root{ --ink:#1a1f26; --soft:#4a535f; --line:#d9dee7; --accent:#b0662a; --code:#f4f6f9; }
*{box-sizing:border-box}
body{font-family:'Malgun Gothic','Apple SD Gothic Neo','Noto Sans KR',system-ui,sans-serif;
  color:var(--ink); line-height:1.7; max-width:900px; margin:0 auto; padding:40px 32px; font-size:15px;}
h1{font-size:1.9rem; line-height:1.25; border-bottom:3px solid var(--accent); padding-bottom:.35em; margin:.2em 0 .8em;}
h2{font-size:1.35rem; margin:2em 0 .6em; padding-left:.5em; border-left:5px solid var(--accent);}
h3{font-size:1.1rem; margin:1.4em 0 .5em; color:#333;}
blockquote{background:#faf6f1; border:1px solid #eadfd2; border-left:4px solid var(--accent);
  margin:1em 0; padding:.8em 1.1em; border-radius:6px; color:var(--soft); font-size:.95em;}
blockquote strong{color:var(--ink);}
table{border-collapse:collapse; width:100%; margin:1em 0; font-size:.9em;}
th,td{border:1px solid var(--line); padding:8px 11px; text-align:left; vertical-align:top;}
th{background:#f2f4f7; font-weight:700;}
code{font-family:Consolas,'D2Coding',monospace; background:#eef1f5; padding:.1em .4em; border-radius:4px; font-size:.88em;}
pre{background:#1c2430; color:#e6edf3; padding:14px 16px; border-radius:8px; overflow-x:auto; font-size:12.5px; line-height:1.55;}
pre code{background:none; color:inherit; padding:0;}
img{max-width:100%; height:auto; border:1px solid var(--line); border-radius:6px; margin:0; display:block;}
hr{border:none; border-top:1px solid var(--line); margin:1.8em 0;}
a{color:var(--accent);}
strong{color:var(--ink);}

/* 그림 */
figure{margin:1.2em 0;}
figure figcaption{font-size:.85em; color:var(--soft); margin-top:.5em; text-align:center;}
/* 인라인 SVG 도표 — currentColor 가 본문 색을 따라간다 */
.svgfig{color:var(--ink); padding:18px 10px; border:1px solid var(--line); border-radius:8px; background:#fcfdfe;}
.svgfig svg{display:block; margin:0 auto; max-width:100%; height:auto;}
.svgfig figcaption{margin-top:1em;}

/* 아직 넣지 않은 이미지 자리 */
.ph{border:2px dashed #c9d2de; border-radius:8px; background:#fafbfd; min-height:190px;
  display:flex; flex-direction:column; align-items:center; justify-content:center;
  gap:.45em; padding:26px 20px; text-align:center;}
.ph .tag{font-family:Consolas,'D2Coding',monospace; font-size:.8em; letter-spacing:.05em;
  color:var(--accent); font-weight:700;}
.ph .what{font-size:.92em; color:var(--soft); max-width:560px;}
.ph .file{font-family:Consolas,'D2Coding',monospace; font-size:.78em; color:#8b95a3;}

/* 좌우 2단 대조 배치 */
.two{display:grid; grid-template-columns:1fr 1fr; gap:14px; align-items:start;}
.two figure{margin:0;}
.two .ph{min-height:220px;}
@media (max-width:700px){ .two{grid-template-columns:1fr;} }

/* 근거 등급 라벨 */
.lb{font-size:.78em; font-weight:700; padding:.12em .45em; border-radius:4px; vertical-align:.08em;}
.lb-f{background:#e6f0e8; color:#2f6b3f;}
.lb-i{background:#fdf1e3; color:#96551f;}
.lb-u{background:#f0eef5; color:#5d5470;}
.todo{background:#fff8e1; border:1px solid #f0dca0; border-radius:4px; padding:.1em .45em; font-size:.85em; color:#8a6d1f;}

@media print{ body{max-width:none; padding:0; font-size:11pt;} h2{page-break-after:avoid;}
  pre,table,img,figure{page-break-inside:avoid;} .ph{min-height:100px;} }
"""

m = re.search(r"<h1[^>]*>(.*?)</h1>", html_body, re.S)
title = re.sub(r"<[^>]+>", "", m.group(1)).strip() if m else "리버싱 챌린지 포트폴리오"

html = f"""<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">
<title>{title}</title>
<style>{CSS}</style></head><body>{html_body}</body></html>"""

os.makedirs(IMGDIR, exist_ok=True)
open(OUT, "w", encoding="utf-8").write(html)

print("built %s  (%d KB)" % (os.path.basename(OUT), len(html) // 1024))
print("내장된 이미지 : %d" % len(embedded))
for s in embedded:
    print("    + %s" % s)
print("빈 자리      : %d" % len(missing))
for s in missing:
    print("    - %s" % s)
if missing:
    print("\n스크린샷을 img/ 에 위 파일명으로 넣고 다시 실행하면 자동으로 들어갑니다.")
