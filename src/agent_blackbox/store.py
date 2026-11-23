"""Persistence for the recorder's JSONL journal and locally trusted public keys."""

import hashlib
import json
import os
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from filelock import FileLock

from .jep import canonicalize


class InvalidJournal(ValueError):
    """A stored record cannot be decoded or disagrees with its signed event."""


class Journal:
    def __init__(self, path: Path):
        self.path = path
        self.lock = FileLock(str(path) + ".lock", timeout=10)

    def records(self):
        if not self.path.exists():
            return
        with self.lock, self.path.open("rb") as stream:
            for number, line in enumerate(stream, start=1):
                try:
                    yield number, json.loads(line)
                except (UnicodeError, ValueError) as exc:
                    raise InvalidJournal(f"Unreadable JSONL record on line {number}") from exc

    def append(self, record):
        line = json.dumps(record, ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"
        with self.lock, self.path.open("a+b") as stream:
            if stream.tell():
                stream.seek(-1, os.SEEK_END)
                if stream.read(1) != b"\n":
                    raise InvalidJournal("Incomplete final JSONL line; restore the journal before appending")
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())


class PublicKeys:
    def __init__(self, directory: Path):
        self.directory = directory

    def path_for(self, who, kid):
        # Hash the pair so actor names and JOSE key IDs never become path components.
        name = hashlib.sha256(canonicalize([who, kid])).hexdigest()
        return self.directory / (name + ".pub")

    def register(self, who, public_key):
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        kid = "ed25519:" + hashlib.sha256(raw).hexdigest()
        path = self.path_for(who, kid)
        self.directory.mkdir(parents=True, exist_ok=True)
        # Publish a complete public key before any event can reference it.
        tmp = NamedTemporaryFile(dir=self.directory, delete=False)
        tmp_path = Path(tmp.name)
        try:
            with tmp:
                tmp.write(raw)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_path, path)
        finally:
            tmp_path.unlink(missing_ok=True)
        return kid

    def lookup(self, who, kid):
        try:
            raw = self.path_for(who, kid).read_bytes()
        except FileNotFoundError:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
