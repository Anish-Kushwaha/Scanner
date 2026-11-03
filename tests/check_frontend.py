#!/usr/bin/env python3
"""Check the rebuilt Scanner pages for broken local links and JS syntax."""
from html.parser import HTMLParser
from pathlib import Path
import shutil, subprocess, sys, tempfile
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PAGES = (ROOT / "index.html", ROOT / "vulnerabilities.html")
ROUTES = {"/", "/health", "/api/scan"}

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.in_script=False; self.attrs={}; self.buffer=[]; self.scripts=[]; self.references=[]
    def handle_starttag(self, tag, attrs):
        attrs=dict(attrs)
        for key in ("href","src"):
            if attrs.get(key): self.references.append(attrs[key])
        if tag.lower()=="script":
            self.in_script=True; self.attrs=attrs; self.buffer=[]
    def handle_data(self,data):
        if self.in_script: self.buffer.append(data)
    def handle_endtag(self,tag):
        if tag.lower()=="script" and self.in_script:
            if not self.attrs.get("src"):
                kind=(self.attrs.get("type") or "").lower()
                if kind in {"","text/javascript","application/javascript","module"}:
                    self.scripts.append(("".join(self.buffer),kind=="module"))
            self.in_script=False; self.attrs={}; self.buffer=[]

def main():
    node=shutil.which("node")
    if not node:
        print("Node.js is required for frontend syntax checks.",file=sys.stderr); return 2
    failures=[]; checked=0
    with tempfile.TemporaryDirectory(prefix="scanner-js-") as temp:
        for page in PAGES:
            if not page.is_file():
                failures.append(f"Missing page: {page.relative_to(ROOT)}"); continue
            parser=PageParser(); parser.feed(page.read_text(encoding="utf-8"))
            for reference in parser.references:
                parsed=urlsplit(reference)
                if parsed.scheme or parsed.netloc or reference.startswith("#"): continue
                path=unquote(parsed.path)
                if not path or path in ROUTES: continue
                candidate=(ROOT/path.lstrip("/")) if path.startswith("/") else page.parent/path
                if not candidate.resolve().is_file(): failures.append(f"{page.name}: missing local reference {reference}")
            for index,(source,module) in enumerate(parser.scripts,1):
                if not source.strip(): continue
                file=Path(temp)/f"{page.stem}-{index}{'.mjs' if module else '.js'}"
                file.write_text(source,encoding="utf-8")
                result=subprocess.run([node,"--check",str(file)],capture_output=True,text=True)
                if result.returncode: failures.append(f"{page.name} script {index}:\\n{result.stdout}{result.stderr}")
                else: checked+=1
    if failures: print("\\n".join(failures),file=sys.stderr); return 1
    print(f"Frontend checks passed: {checked} JavaScript blocks across {len(PAGES)} pages."); return 0

if __name__=="__main__": raise SystemExit(main())
