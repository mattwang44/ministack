"""Unit tests for the blob-on-disk persistence refactor in services/lambda_svc.py.

These talk to the in-process module — no ministack server required, no docker.
They exercise get_state/restore_state round-trip and the on-disk blob shape.

Compared to tests/test_lambda.py's end-to-end suite (which boots a real
ministack and uses boto3), these tests:
  - Run fast (no I/O beyond local tmpdir)
  - Don't depend on docker, network, or persistence environment vars
  - Are the right granularity to catch regressions in the
    code_zip → blob_ref round-trip introduced by the PoC
"""

import base64
import hashlib
import importlib
import json
import os
from unittest import mock

import pytest


@pytest.fixture
def lambda_svc(tmp_path, monkeypatch):
    """Reload the lambda_svc module with a fresh STATE_DIR pointing at tmp_path,
    so each test gets isolated _functions state + blob storage."""
    monkeypatch.setenv("STATE_DIR", str(tmp_path))
    monkeypatch.setenv("PERSIST_STATE", "1")
    from ministack.core import persistence as p
    importlib.reload(p)
    from ministack.services import lambda_svc as svc
    importlib.reload(svc)
    yield svc
    # Cleanup
    svc._functions.clear()
    svc._layers.clear()
    svc._esms.clear()
    svc._function_urls.clear()


def _make_func(name: str, code_zip: bytes, versions: dict | None = None) -> dict:
    return {
        "config": {
            "FunctionName": name,
            "FunctionArn": f"arn:aws:lambda:us-east-1:000000000000:function:{name}",
            "Runtime": "python3.12",
            "Handler": "index.handler",
        },
        "code_zip": code_zip,
        "versions": versions or {},
        "next_version": 1,
        "tags": {},
        "policy": {"Version": "2012-10-17", "Id": "default", "Statement": []},
    }


# ── Core: bytes → ref → bytes round-trip ────────────────────────────────


def test_get_state_replaces_bytes_with_blob_ref(lambda_svc):
    """get_state should NOT emit raw bytes or base64; only a sha256 ref."""
    code = b"def handler(event, context): return 'hello'\n" * 100  # ~4 KB
    lambda_svc._functions["my-fn"] = _make_func("my-fn", code)

    state = lambda_svc.get_state()
    fn_state = next(iter(state["functions"]._data.values()))

    assert isinstance(fn_state["code_zip"], dict), \
        "code_zip should be replaced with a ref dict, not kept as bytes/str"
    assert set(fn_state["code_zip"].keys()) == {"code_blob_ref"}
    assert fn_state["code_zip"]["code_blob_ref"] == hashlib.sha256(code).hexdigest()


def test_blob_file_written_to_lambda_blobs_dir(lambda_svc, tmp_path):
    """The bytes must end up in {STATE_DIR}/lambda-blobs/{sha}.zip."""
    code = b"some lambda zip bytes"
    lambda_svc._functions["fn"] = _make_func("fn", code)

    lambda_svc.get_state()

    sha = hashlib.sha256(code).hexdigest()
    blob_path = tmp_path / "lambda-blobs" / f"{sha}.zip"
    assert blob_path.exists(), f"blob not written at {blob_path}"
    assert blob_path.read_bytes() == code


def test_restore_state_round_trips_bytes(lambda_svc):
    """Save → clear → restore should put the original bytes back in _functions."""
    code = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1000  # non-utf8 bytes
    lambda_svc._functions["fn"] = _make_func("fn", code)

    state = lambda_svc.get_state()
    lambda_svc._functions.clear()

    lambda_svc.restore_state(state)

    restored = lambda_svc._functions._data[("000000000000", "fn")]
    assert restored["code_zip"] == code
    assert isinstance(restored["code_zip"], bytes), \
        "restore must hand back bytes, not the ref dict"


def test_versions_code_zip_also_blob_refed(lambda_svc):
    """Per-version code_zip blobs go through the same path."""
    v1_code = b"v1 code"
    v2_code = b"v2 code"
    fn = _make_func("fn", v2_code, versions={
        "1": {"code_zip": v1_code, "config": {"Version": "1"}},
    })
    lambda_svc._functions["fn"] = fn

    state = lambda_svc.get_state()
    fn_state = state["functions"]._data[("000000000000", "fn")]
    v1_state = fn_state["versions"]["1"]

    assert isinstance(v1_state["code_zip"], dict)
    assert v1_state["code_zip"]["code_blob_ref"] == hashlib.sha256(v1_code).hexdigest()
    assert isinstance(fn_state["code_zip"], dict)
    assert fn_state["code_zip"]["code_blob_ref"] == hashlib.sha256(v2_code).hexdigest()

    # Round-trip back through restore
    lambda_svc._functions.clear()
    lambda_svc.restore_state(state)
    restored = lambda_svc._functions._data[("000000000000", "fn")]
    assert restored["code_zip"] == v2_code
    assert restored["versions"]["1"]["code_zip"] == v1_code


def test_identical_code_dedups_to_one_blob_file(lambda_svc, tmp_path):
    """Two Lambdas with byte-identical code should share one on-disk file (content-addressed)."""
    code = b"same code for both lambdas"
    lambda_svc._functions["fn-a"] = _make_func("fn-a", code)
    lambda_svc._functions["fn-b"] = _make_func("fn-b", code)

    lambda_svc.get_state()

    blob_dir = tmp_path / "lambda-blobs"
    files = list(blob_dir.iterdir())
    assert len(files) == 1, f"expected dedup to 1 blob file, got {[f.name for f in files]}"
    assert files[0].name == f"{hashlib.sha256(code).hexdigest()}.zip"


# ── lambda.json size: the actual point of the PoC ──────────────────────


def test_lambda_json_does_not_inline_code_bytes(lambda_svc, tmp_path):
    """The serialized JSON should NOT contain the code blob — just refs.
    This is the property that fixes the 1+ GB lambda.json bloat."""
    big_code = b"X" * (5 * 1024 * 1024)  # 5 MB synthetic zip
    lambda_svc._functions["fat-fn"] = _make_func("fat-fn", big_code)

    state = lambda_svc.get_state()
    serialized = json.dumps(state, default=_json_default_for_test)

    # Hard upper bound: the entire state JSON must be much smaller than the code blob.
    # In the OLD design this would be ~6.7 MB (5 MB base64-encoded ≈ 1.34× original).
    assert len(serialized) < 100 * 1024, \
        f"state JSON ballooned to {len(serialized):,} bytes — code blob is still inline"
    # And no base64 of the big code should appear inline.
    assert base64.b64encode(big_code).decode() not in serialized


# ── Backward compat: legacy persistence files (base64 inline) still load ──


def test_legacy_base64_inline_persistence_still_loads(lambda_svc):
    """Old persistence files stored code_zip as base64-encoded str.
    restore_state must still accept that shape — no one-shot migration required."""
    from ministack.core.responses import AccountScopedDict

    code = b"legacy code"
    legacy_state = {
        "functions": AccountScopedDict(),
        "layers": AccountScopedDict(),
        "esms": AccountScopedDict(),
        "function_urls": AccountScopedDict(),
        "kinesis_positions": {},
        "dynamodb_stream_positions": {},
    }
    legacy_state["functions"]._data[("000000000000", "old-fn")] = {
        "config": {"FunctionName": "old-fn"},
        "code_zip": base64.b64encode(code).decode(),  # legacy inline shape
        "versions": {},
    }

    lambda_svc.restore_state(legacy_state)

    restored = lambda_svc._functions._data[("000000000000", "old-fn")]
    assert restored["code_zip"] == code


# ── Robustness: missing blob doesn't crash restore ──────────────────────


def test_restore_with_missing_blob_drops_code_doesnt_crash(lambda_svc, tmp_path, caplog):
    """If a blob file vanishes between save and restore (e.g. partial volume mount),
    restore should log an error and set code_zip=None — not raise."""
    from ministack.core.responses import AccountScopedDict
    state = {
        "functions": AccountScopedDict(),
        "layers": AccountScopedDict(),
        "esms": AccountScopedDict(),
        "function_urls": AccountScopedDict(),
        "kinesis_positions": {},
        "dynamodb_stream_positions": {},
    }
    state["functions"]._data[("000000000000", "orphan")] = {
        "config": {"FunctionName": "orphan"},
        "code_zip": {"code_blob_ref": "deadbeef" * 8},  # no such blob
        "versions": {},
    }

    # Should not raise.
    lambda_svc.restore_state(state)

    restored = lambda_svc._functions._data[("000000000000", "orphan")]
    assert restored["code_zip"] is None


# ── helper ─────────────────────────────────────────────────────────────


def _json_default_for_test(o):
    """Local JSON encoder for the size test — handles AccountScopedDict + bytes."""
    from ministack.core.responses import AccountScopedDict
    if isinstance(o, AccountScopedDict):
        return {f"{k[0]}\x00{k[1]!r}": v for k, v in o._data.items()}
    if isinstance(o, (bytes, bytearray)):
        return base64.b64encode(bytes(o)).decode()
    raise TypeError(type(o).__name__)
