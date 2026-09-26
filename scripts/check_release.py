"""Reject release tags whose built Python metadata disagrees with VERSION."""
from email.parser import BytesParser
from pathlib import Path
import re
import tarfile
import tomllib
import zipfile

version = Path("VERSION").read_text().strip()
project = tomllib.loads(Path("pyproject.toml").read_text())["project"]
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:a[0-9]+)?", version), version
assert project["version"] == version, "VERSION differs from pyproject.toml"
def check(raw):
    metadata = BytesParser().parsebytes(raw)
    assert metadata["Version"] == version, "Built package has a different version"
    normalize = lambda text: re.sub(r"[-_.]+", "-", text).lower()
    assert normalize(metadata["Name"]) == normalize(project["name"]), "Wrong distribution name"

wheels, sources = list(Path("dist").glob("*.whl")), list(Path("dist").glob("*.tar.gz"))
assert len(wheels) == len(sources) == 1, "Expected one wheel and one source distribution"
with zipfile.ZipFile(wheels[0]) as archive:
    names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
    assert len(names) == 1
    check(archive.read(names[0]))
with tarfile.open(sources[0]) as archive:
    names = [name for name in archive.getnames() if name.count("/") == 1 and name.endswith("/PKG-INFO")]
    assert len(names) == 1
    check(archive.extractfile(names[0]).read())
print(f"Release metadata verified: {project['name']} {version}")
