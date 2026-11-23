import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_blackbox import AgentBlackbox


def record(storage):
    result = subprocess.run(
        [sys.executable, str(Path(__file__).with_name("record_sample.py")), str(storage)],
        check=True, capture_output=True, text=True,
    )
    return json.loads(result.stdout)


def read(storage, *args, code=0):
    result = subprocess.run(
        [sys.executable, "-m", "agent_blackbox.cli", "--storage", str(storage), *args],
        capture_output=True, text=True,
    )
    assert result.returncode == code, result.stderr
    report = json.loads(result.stdout)
    if code:
        assert report["verification_status"] in result.stderr
    return report


def test_separate_recorders_and_readers(tmp_path):
    first = record(tmp_path)
    second = record(tmp_path)
    assert first != second
    for batch in (first, second):
        parent, child = batch["parent"], batch["child"]
        for event_hash in (parent, child):
            assert read(tmp_path, "verify", event_hash)["valid"]
        review = read(tmp_path, "review", child)
        assert review["verification_status"] == "verified"
        assert [node["event_hash"] for node in review["chain"]] == [parent, child]
        assert (review["candidate_failure_node"], review["score_basis"], review["review_score"]) == (
            "planner", "declared_ancestor_failed", 0.62,
        )
        assert read(tmp_path, "tree", parent)["children"][0]["hash"] == child
        assert read(tmp_path, "blame", parent)["score_basis"] == "selected_event_failed"
    assert len(list((tmp_path / "trusted-keys").glob("*.pub"))) == 4


def test_independent_trust_store_and_missing_event(tmp_path):
    sample = record(tmp_path)
    child = sample["child"]
    keys = tmp_path / "separate-trust"
    (tmp_path / "trusted-keys").rename(keys)
    assert read(tmp_path, "--trusted-keys", str(keys), "verify", child)["valid"]
    assert read(tmp_path, "verify", child, code=4)["verification_status"] == "unknown_key"
    assert read(tmp_path, "review", child, code=4)["problem_event"] == sample["parent"]
    absent = "sha256:" + "0" * 64
    assert read(tmp_path, "verify", absent, code=3)["valid"] is False
    assert read(tmp_path, "review", absent, code=3)["score_basis"] == "event_not_found"


def test_wrong_public_key_fails_verification(tmp_path):
    sample = record(tmp_path)
    keys = list((tmp_path / "trusted-keys").glob("*.pub"))
    assert len(keys) == 2
    keys[0].write_bytes(keys[1].read_bytes())
    report = read(tmp_path, "review", sample["child"], code=5)
    assert report["verification_status"] == "invalid_record"


@pytest.mark.parametrize("change", ["truncated", "metadata"])
def test_invalid_journal_reports_line(tmp_path, change):
    child = record(tmp_path)["child"]
    path = tmp_path / "events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    if change == "metadata":
        row = json.loads(lines[1])
        row["status"] = "failed"
        lines[1] = json.dumps(row)
    else:
        lines[1] = "{"
    path.write_text("\n".join(lines), encoding="utf-8")
    result = read(tmp_path, "verify", child, code=5)
    assert "line 2" in result["detail"]
    assert result["valid"] is False


def test_missing_declared_parent_and_storage_error(tmp_path):
    missing = "sha256:" + "0" * 64
    box = AgentBlackbox(str(tmp_path))

    @box.trace("orphan", parent_event_hash=missing)
    def run():
        return "done"

    run()
    child = next(iter(box.events))
    assert read(tmp_path, "verify", child)["valid"]
    assert read(tmp_path, "review", child, code=3)["problem_event"] == missing
    result = read(tmp_path / "events.jsonl", "verify", child, code=6)
    assert result["verification_status"] == "storage_error"
