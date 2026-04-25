import io
import json
import os
import time
import zipfile
from urllib.parse import urlparse
import pytest
from botocore.exceptions import ClientError
import uuid as _uuid_mod

def test_sts_get_caller_identity(sts):
    resp = sts.get_caller_identity()
    assert resp["Account"] == "000000000000"

def test_sts_assume_role_returns_credentials(sts):
    resp = sts.assume_role(
        RoleArn="arn:aws:iam::000000000000:role/test-role",
        RoleSessionName="intg-session",
    )
    creds = resp["Credentials"]
    assert "AccessKeyId" in creds
    assert "SecretAccessKey" in creds
    assert "SessionToken" in creds
    assert "Expiration" in creds
    assert resp["AssumedRoleUser"]["Arn"]

def test_sts_get_access_key_info(sts):
    resp = sts.get_access_key_info(AccessKeyId="AKIAIOSFODNN7EXAMPLE")
    assert "Account" in resp
    assert resp["Account"] == "000000000000"

def test_sts_get_caller_identity_full(sts):
    resp = sts.get_caller_identity()
    assert resp["Account"] == "000000000000"
    assert "Arn" in resp
    assert "UserId" in resp

def test_sts_assume_role(sts):
    resp = sts.assume_role(
        RoleArn="arn:aws:iam::000000000000:role/iam-test-role",
        RoleSessionName="test-session",
        DurationSeconds=900,
    )
    creds = resp["Credentials"]
    assert creds["AccessKeyId"].startswith("ASIA")
    assert len(creds["SecretAccessKey"]) > 0
    assert len(creds["SessionToken"]) > 0
    assert "Expiration" in creds

    assumed = resp["AssumedRoleUser"]
    assert "test-session" in assumed["Arn"]
    assert "AssumedRoleId" in assumed

def test_sts_get_session_token(sts):
    resp = sts.get_session_token(DurationSeconds=900)
    creds = resp["Credentials"]
    assert "AccessKeyId" in creds
    assert "SecretAccessKey" in creds
    assert "SessionToken" in creds
    assert "Expiration" in creds

def test_sts_assume_role_with_web_identity(sts, iam):
    iam.create_role(
        RoleName="test-oidc-role",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )
    role_arn = f"arn:aws:iam::000000000000:role/test-oidc-role"
    resp = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName="ci-session",
        WebIdentityToken="fake-oidc-token-value",
    )
    creds = resp["Credentials"]
    assert "AccessKeyId" in creds
    assert "SecretAccessKey" in creds
    assert "SessionToken" in creds
    assert "Expiration" in creds


def test_sts_get_caller_identity_reflects_assumed_role(sts):
    """After AssumeRole, GetCallerIdentity called with the new credentials
    must return the assumed-role ARN, not the root identity. This is what
    AWS does in production — workloads relying on identity-aware logging
    or audit trails depend on it."""
    import boto3
    from botocore.config import Config
    role_arn = "arn:aws:iam::000000000000:role/identity-probe"
    session_name = "probe-session-1"
    assumed = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    creds = assumed["Credentials"]
    expected_arn = f"arn:aws:iam::000000000000:assumed-role/identity-probe/{session_name}"
    expected_user_id = assumed["AssumedRoleUser"]["AssumedRoleId"]
    sts2 = boto3.client(
        "sts",
        endpoint_url=os.environ.get("MINISTACK_ENDPOINT", "http://localhost:4566"),
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
        config=Config(retries={"mode": "standard"}),
    )
    ident = sts2.get_caller_identity()
    assert ident["Arn"] == expected_arn
    assert ident["UserId"] == expected_user_id
    assert ident["Account"] == "000000000000"


def test_sts_get_caller_identity_unsigned_returns_root(sts):
    """Without AssumeRole, GetCallerIdentity returns the root identity for
    the configured account."""
    resp = sts.get_caller_identity()
    assert resp["Arn"] == "arn:aws:iam::000000000000:root"


def test_sts_persistence_registered_in_app_state_map():
    """STS now holds AssumeRole session state, so it must be wired into
    app.py's PERSIST_STATE shutdown loop. Without this entry the
    sts.get_state() callback never fires and assumed-role identity
    silently disappears across restarts."""
    import inspect
    from ministack import app
    src = inspect.getsource(app)
    assert '"sts": "sts"' in src, (
        "STS not registered in app.py PERSIST_STATE _state_map — "
        "assumed-role sessions will not survive container restart"
    )


def test_sts_get_state_round_trip_preserves_sessions():
    """get_state() / restore_state() preserve the assumed-role session
    map. This is what the persistence loop calls on shutdown and
    startup; if the round-trip drops sessions, GetCallerIdentity will
    return :root after restart even though credentials are still valid."""
    from ministack.services import sts as sts_mod

    original = sts_mod.get_state()
    try:
        sts_mod._assumed_role_sessions["ASIA-PROBE-KEY"] = {
            "arn": "arn:aws:iam::000000000000:assumed-role/probe/sess",
            "user_id": "AROA-X:sess",
        }
        snapshot = sts_mod.get_state()
        assert "assumed_role_sessions" in snapshot

        sts_mod.reset()
        assert "ASIA-PROBE-KEY" not in sts_mod._assumed_role_sessions

        sts_mod.restore_state(snapshot)
        restored = sts_mod._assumed_role_sessions.get("ASIA-PROBE-KEY")
        assert restored is not None
        assert restored["arn"].endswith("/probe/sess")
    finally:
        sts_mod.reset()
        sts_mod.restore_state(original)


def test_sts_assume_role_with_web_identity_tracks_session(sts, iam):
    """AssumeRoleWithWebIdentity must also be reachable from GetCallerIdentity."""
    import boto3
    from botocore.config import Config
    iam.create_role(
        RoleName="oidc-identity-probe",
        AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}',
    )
    role_arn = f"arn:aws:iam::000000000000:role/oidc-identity-probe"
    session_name = "oidc-session-1"
    resp = sts.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName=session_name,
        WebIdentityToken="fake-oidc-token-value",
    )
    creds = resp["Credentials"]
    sts2 = boto3.client(
        "sts",
        endpoint_url=os.environ.get("MINISTACK_ENDPOINT", "http://localhost:4566"),
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
        region_name="us-east-1",
        config=Config(retries={"mode": "standard"}),
    )
    ident = sts2.get_caller_identity()
    expected_arn = f"arn:aws:iam::000000000000:assumed-role/oidc-identity-probe/{session_name}"
    assert ident["Arn"] == expected_arn
