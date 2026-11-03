#!/usr/bin/env python3
"""Extract inline JavaScript from the static pages and syntax-check it with Node."""
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PAGES = (ROOT / "index.html", ROOT / "vulnerabilities.html")


class ScriptExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.in_script = False
        self.attributes = {}
        self.buffer = []
        self.scripts = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            self.in_script = True
            self.attributes = dict(attrs)
            self.buffer = []

    def handle_data(self, data):
        if self.in_script:
            self.buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self.in_script:
            if not self.attributes.get("src"):
                script_type = (self.attributes.get("type") or "").lower()
                if script_type in {"", "text/javascript", "application/javascript", "module"}:
                    self.scripts.append(("".join(self.buffer), self.attributes.get("type") == "module"))
            self.in_script = False
            self.attributes = {}
            self.buffer = []


def main():
    node = shutil.which("node")
    if not node:
        print("Node.js is required for frontend syntax checks.", file=sys.stderr)
        return 2

    checked = 0
    with tempfile.TemporaryDirectory(prefix="scanner-js-") as temp_dir:
        for page in PAGES:
            if not page.is_file():
                print(f"Missing frontend page: {page.relative_to(ROOT)}", file=sys.stderr)
                return 1
            parser = ScriptExtractor()
            parser.feed(page.read_text(encoding="utf-8"))
            for index, (source, is_module) in enumerate(parser.scripts, 1):
                if not source.strip():
                    continue
                suffix = ".mjs" if is_module else ".js"
                temp_file = Path(temp_dir) / f"{page.stem}-{index}{suffix}"
                temp_file.write_text(source, encoding="utf-8")
                result = subprocess.run(
                    [node, "--check", str(temp_file)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode:
                    print(
                        f"JavaScript syntax error in {page.relative_to(ROOT)} inline script {index}:\n"
                        f"{result.stdout}{result.stderr}",
                        file=sys.stderr,
                    )
                    return result.returncode
                checked += 1

    print(f"JavaScript syntax OK: {checked} inline scripts across {len(PAGES)} pages.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
