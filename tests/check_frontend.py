#!/usr/bin/env python3
"""Validate local page links and syntax-check inline JavaScript with Node."""
from html.parser import HTMLParser
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parents[1]
PAGES = (
    ROOT / "index.html",
    ROOT / "vulnerabilities.html",
    ROOT / "disclosure.html",
    ROOT / "creator.html",
)
ROUTES = {"/", "/health", "/api/scan"}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.in_script = False
        self.attributes = {}
        self.buffer = []
        self.scripts = []
        self.local_references = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "script":
            self.in_script = True
            self.attributes = attrs
            self.buffer = []
        for attr in ("href", "src"):
            value = attrs.get(attr)
            if value:
                self.local_references.append(value)

    def handle_data(self, data):
        if self.in_script:
            self.buffer.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self.in_script:
            if not self.attributes.get("src"):
                script_type = (self.attributes.get("type") or "").lower()
                if script_type in {"", "text/javascript", "application/javascript", "module"}:
                    self.scripts.append(("".join(self.buffer), script_type == "module"))
            self.in_script = False
            self.attributes = {}
            self.buffer = []


def check_local_references(page, references):
    failures = []
    for reference in references:
        parsed = urlsplit(reference)
        if parsed.scheme or parsed.netloc or reference.startswith(("#", "javascript:")):
            continue
        path = unquote(parsed.path)
        if not path:
            continue
        if path in ROUTES:
            continue
        if path.startswith("/"):
            candidate = (ROOT / path.lstrip("/")).resolve()
        else:
            candidate = (page.parent / path).resolve()
        try:
            candidate.relative_to(ROOT)
        except ValueError:
            failures.append(f"{page.name}: reference escapes repository root: {reference}")
            continue
        if not candidate.is_file():
            failures.append(f"{page.name}: missing local asset/page: {reference}")
    return failures


def main():
    node = shutil.which("node")
    if not node:
        print("Node.js is required for frontend syntax checks.", file=sys.stderr)
        return 2

    checked = 0
    failures = []
    with tempfile.TemporaryDirectory(prefix="scanner-js-") as temp_dir:
        for page in PAGES:
            if not page.is_file():
                failures.append(f"Missing frontend page: {page.relative_to(ROOT)}")
                continue
            parser = PageParser()
            parser.feed(page.read_text(encoding="utf-8"))
            failures.extend(check_local_references(page, parser.local_references))
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
                    failures.append(
                        f"JavaScript syntax error in {page.relative_to(ROOT)} "
                        f"inline script {index}:\n{result.stdout}{result.stderr}"
                    )
                else:
                    checked += 1

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(
        f"Frontend OK: {checked} inline JavaScript blocks and all local "
        f"links/assets across {len(PAGES)} pages."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
