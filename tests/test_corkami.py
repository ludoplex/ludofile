from hashlib import md5
from pathlib import Path
import re
import shutil
import subprocess
from tempfile import TemporaryDirectory
from typing import Set
from unittest import TestCase
import urllib.request
from zipfile import ZipFile, ZipInfo

from polyfile.magic import MAGIC_DEFS, MagicMatcher, MatchContext

CORKAMI_CORPUS_ZIP = Path(__file__).absolute().parent / "corkami.zip"
FAILED_FILE_DIR = Path(__file__).absolute().parent / "failed_corkami_files"
CORKAMI_URL = "https://github.com/corkami/pocs/archive/refs/heads/master.zip"
SCRIPT_DIR = Path(__file__).absolute().parent
FILE_DIR = SCRIPT_DIR.parent / "file"
FILE_PATH = FILE_DIR / "src" / "file"
MAGIC_FILE_PATH = SCRIPT_DIR / "magic.mgc"

KNOWN_BAD_FILES = {
    "1d52f82b2a240cb618effe344bb1e579",  # jpg.bin
                                         # `file` incorrectly classifies this as `text/plain`
                                         # while PolyFile more correctly classifies it as application/octet-stream
    "bdb7963176bdaa12a17d98db9cbf384b",  # make.py
                                         # `file` correctly classifies this as `text/x-script.python`
                                         # while PolyFile incorrectly classifies this as `text/plain` (investigating)
}

class CorkamiCorpusTest(TestCase):
    default_matcher: MagicMatcher

    @classmethod
    def setUpClass(cls):
        if FAILED_FILE_DIR.exists():
            shutil.rmtree(FAILED_FILE_DIR)
        # skip the DER definition because we don't yet support it (and none of the tests actually require it)
        cls.default_matcher = MagicMatcher.parse(*(d for d in MAGIC_DEFS if d.name != "der"))


if not CORKAMI_CORPUS_ZIP.exists():
    with urllib.request.urlopen(CORKAMI_URL) as response, open(CORKAMI_CORPUS_ZIP, "wb") as out_file:
        shutil.copyfileobj(response, out_file)


FILE_MIMETYPE_PATTERN = re.compile(rb"^(.*?:|-)\s*(?P<mime>[^/\s]+/[^/;\s]+)\s*(;.*?$|$)(?P<remainder>.*)",
                                   re.MULTILINE)


def test_file(self: CorkamiCorpusTest, info: ZipInfo):
    with TemporaryDirectory() as tmpdir:
        with ZipFile(CORKAMI_CORPUS_ZIP, "r") as z:
            file_path = z.extract(info, tmpdir)
            # see if this is a known bad file
            with open(file_path, "rb") as f:
                md5_hash = md5(f.read()).hexdigest().lower()
                if md5_hash in KNOWN_BAD_FILES:
                    print(f"Skipping known bad file {info.filename}")
                    return
        orig_file_output = subprocess.check_output([
            str(FILE_PATH), "-m", str(MAGIC_FILE_PATH), "-i", "--keep-going", str(file_path)
        ])
        file_output = orig_file_output
        file_mimetypes: Set[str] = set()
        while file_output:
            m = FILE_MIMETYPE_PATTERN.match(file_output)
            if not m:
                break
            file_mimetypes.add(m.group("mime").decode("utf-8"))
            file_output = m.group("remainder")
        polyfile_mimetypes = {
            mimetype
            for match in self.default_matcher.match(MatchContext.load(file_path, only_match_mime=True))
            for mimetype in match.mimetypes
        }
        if len(file_mimetypes & polyfile_mimetypes) != len(file_mimetypes):
            # there are some mimetypes that `file` matched by PolyFile missed
            if "application/octet-stream" in file_mimetypes and "application/octet-stream" not in polyfile_mimetypes:
                # this is just `file`'s default mime type, so take it out
                file_mimetypes -= {"application/octet-stream"}
            if len(file_mimetypes) != len(file_mimetypes & polyfile_mimetypes):
                # PolyFile is more accurate than `file` at detecting PDFs:
                missed_mimetypes = file_mimetypes - polyfile_mimetypes
                if len(missed_mimetypes) == 1 and "text/plain" in missed_mimetypes and "application/pdf" in \
                        polyfile_mimetypes:
                    # PolyFile just detected a PDF that `file` misclassified as text/plain!
                    pass
                else:
                    if not FAILED_FILE_DIR.exists():
                        FAILED_FILE_DIR.mkdir()
                    suffix = 1
                    file_path = Path(file_path)
                    out_file = FAILED_FILE_DIR / file_path.name
                    while out_file.exists():
                        suffix += 1
                        out_file = FAILED_FILE_DIR / f"{file_path.stem}{suffix}{file_path.suffix}"
                    shutil.move(file_path, out_file)
                    self.fail(f"`file` matched {file_mimetypes - polyfile_mimetypes!r} but PolyFile matched "
                              f"{polyfile_mimetypes - file_mimetypes}.\nOriginal `file` output was: "
                              f"{orig_file_output!r}")


def _init_tests():
    with ZipFile(CORKAMI_CORPUS_ZIP, "r") as z:
        for info in z.infolist():
            if info.is_dir() or info.file_size <= 0:
                continue
            path = Path(info.filename)
            if path.name.startswith("."):
                continue

            suffix = ""
            func_name = f"test_{path.name.replace('.', '_')}"
            while hasattr(CorkamiCorpusTest, f"{func_name}{suffix}"):
                if not suffix:
                    suffix = 2
                else:
                    suffix += 1

            def test(self: CorkamiCorpusTest, info=info):
                return test_file(self, info)

            setattr(CorkamiCorpusTest, f"{func_name}{suffix}", test)


def build_local_file():
    """Builds the local version of `file`"""
    if not FILE_DIR.exists():
        print("Cloning the `file` git submodule...")
        subprocess.check_call(["git", "submodule", "update", "--init", "--recursive"], cwd=str(FILE_DIR.parent))
        if not FILE_DIR.exists():
            raise ValueError("Could not init the `file` git submodule")
    configure_path = FILE_DIR / "configure"
    if not configure_path.exists():
        print("Running autoreconf...")
        subprocess.check_call(["autoreconf", "-f", "-i"], cwd=str(FILE_DIR))
        if not configure_path.exists():
            raise ValueError(f"Error running autoreconf to build {configure_path}")
    makefile_path = FILE_DIR / "Makefile"
    if not makefile_path.exists():
        print("Configuring the `file` build")
        subprocess.check_call(["./configure", "--disable-silent-rules"], cwd=str(FILE_DIR))
        if not makefile_path.exists():
            raise ValueError(f"Error running ./configure to build {makefile_path}")
    print("Recompiling `file`...")
    subprocess.check_call(["make"], cwd=str(FILE_DIR))
    magdir = FILE_DIR / "magic" / "Magdir"
    assert magdir.exists()
    print("Recompiling PolyFile's magic definitions...")
    subprocess.check_call([str(FILE_PATH), "-m", str(magdir), "-C"], cwd=str(SCRIPT_DIR))
    mgc_file = SCRIPT_DIR / f"{magdir.name}.mgc"
    assert mgc_file.exists()
    if MAGIC_FILE_PATH.exists():
        MAGIC_FILE_PATH.unlink()
    mgc_file.rename(MAGIC_FILE_PATH)


build_local_file()
_init_tests()
