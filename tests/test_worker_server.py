import base64
import io
import tempfile
import unittest
import zipfile
from pathlib import Path

from worker_server import safe_extract_archive


class ArchiveSafetyTests(unittest.TestCase):
    def make_archive(self, name, body=b"sample"):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(name, body)
        return base64.b64encode(stream.getvalue()).decode()

    def test_extracts_regular_source_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            safe_extract_archive(self.make_archive("src/app.py", b"print('ok')"), root)
            self.assertEqual((root / "src/app.py").read_bytes(), b"print('ok')")

    def test_rejects_parent_traversal(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                safe_extract_archive(self.make_archive("../outside.txt"), Path(temp))

    def test_rejects_absolute_paths(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                safe_extract_archive(self.make_archive("/tmp/outside.txt"), Path(temp))


if __name__ == "__main__":
    unittest.main()
