"""
STS Service Emulator (AWS-compatible).

Actions:
  GetCallerIdentity, AssumeRole, AssumeRoleWithWebIdentity,
  GetSessionToken, GetAccessKeyInfo.
"""

import copy
import json
import re
import time
from urllib.parse import parse_qs

from ministack.core.responses import AccountScopedDict, get_account_id, json_response, new_uuid
from ministack.core.persistence import load_state
# Shared helpers — IAM and STS are a natural pair; STS is stateless
# (modulo assumed-role session tracking) and reuses IAM's XML builders
# and credential generators.
from ministack.services.iam import _p, _xml, _error, _future, \
    _gen_session_access_key, _gen_secret, _gen_session_token


# AccessKeyId -> {arn, user_id} for sessions issued via AssumeRole /
# AssumeRoleWithWebIdentity. Lets GetCallerIdentity reflect the assumed
# identity instead of always returning :root.
_assumed_role_sessions = AccountScopedDict()


_CRED_RE = re.compile(r"Credential=([A-Z0-9]+)/")


def get_state():
    return {"assumed_role_sessions": copy.deepcopy(_assumed_role_sessions)}


def restore_state(data):
    if not data:
        return
    _assumed_role_sessions.update(data.get("assumed_role_sessions", {}))


def reset():
    _assumed_role_sessions.clear()


try:
    _restored = load_state("sts")
    if _restored:
        restore_state(_restored)
except Exception:
    import logging
    logging.getLogger(__name__).exception(
        "Failed to restore persisted STS state; continuing fresh"
    )


def _extract_access_key_id(headers):
    """Pull the AccessKeyId out of a SigV4 Authorization header.
    Returns None when the request is unsigned or non-SigV4."""
    auth = headers.get("authorization") or headers.get("Authorization") or ""
    match = _CRED_RE.search(auth)
    return match.group(1) if match else None


async def handle_request(method, path, headers, body, query_params):
    params = dict(query_params)
    content_type = headers.get("content-type", "")
    target = headers.get("x-amz-target", "")

    # JSON protocol (newer SDKs): X-Amz-Target: AWSSecurityTokenServiceV20110615.ActionName
    if "amz-json" in content_type and target.startswith("AWSSecurityTokenServiceV20110615."):
        action_name = target.split(".")[-1]
        params["Action"] = [action_name]
        if body:
            try:
                json_body = json.loads(body)
                for k, v in json_body.items():
                    params[k] = [str(v)] if not isinstance(v, list) else v
            except (json.JSONDecodeError, TypeError):
                pass
    elif method == "POST" and body:
        for k, v in parse_qs(body.decode("utf-8", errors="replace")).items():
            params[k] = v

    action = _p(params, "Action")
    use_json = "amz-json" in content_type

    if action == "GetCallerIdentity":
        # If the calling credentials map to a tracked assumed-role session,
        # return that identity; otherwise default to :root. Real AWS does
        # the same lookup in IAM.
        access_key_id = _extract_access_key_id(headers)
        session = _assumed_role_sessions.get(access_key_id) if access_key_id else None
        if session:
            arn = session["arn"]
            user_id = session["user_id"]
        else:
            arn = f"arn:aws:iam::{get_account_id()}:root"
            user_id = get_account_id()
        if use_json:
            return json_response({"Account": get_account_id(), "Arn": arn, "UserId": user_id})
        return _xml(200, "GetCallerIdentityResponse",
                    f"<GetCallerIdentityResult>"
                    f"<Arn>{arn}</Arn>"
                    f"<UserId>{user_id}</UserId>"
                    f"<Account>{get_account_id()}</Account>"
                    f"</GetCallerIdentityResult>",
                    ns="sts")

    if action == "AssumeRole":
        role_arn = _p(params, "RoleArn")
        session_name = _p(params, "RoleSessionName")
        duration = int(_p(params, "DurationSeconds") or 3600)
        expiration = _future(duration)
        access_key = _gen_session_access_key()
        secret_key = _gen_secret()
        session_token = _gen_session_token()
        role_id = "AROA" + new_uuid().replace("-", "")[:17].upper()
        assumed_arn = role_arn.replace(":role/", ":assumed-role/", 1)
        if not assumed_arn.endswith(f"/{session_name}"):
            assumed_arn = f"{assumed_arn}/{session_name}"
        assumed_user_id = f"{role_id}:{session_name}"
        _assumed_role_sessions[access_key] = {"arn": assumed_arn, "user_id": assumed_user_id}
        if use_json:
            return json_response({
                "Credentials": {"AccessKeyId": access_key, "SecretAccessKey": secret_key, "SessionToken": session_token, "Expiration": time.time() + duration},
                "AssumedRoleUser": {"AssumedRoleId": assumed_user_id, "Arn": assumed_arn},
                "PackedPolicySize": 0,
            })
        return _xml(200, "AssumeRoleResponse",
                    f"<AssumeRoleResult>"
                    f"<Credentials>"
                    f"<AccessKeyId>{access_key}</AccessKeyId>"
                    f"<SecretAccessKey>{secret_key}</SecretAccessKey>"
                    f"<SessionToken>{session_token}</SessionToken>"
                    f"<Expiration>{expiration}</Expiration>"
                    f"</Credentials>"
                    f"<AssumedRoleUser>"
                    f"<AssumedRoleId>{assumed_user_id}</AssumedRoleId>"
                    f"<Arn>{assumed_arn}</Arn>"
                    f"</AssumedRoleUser>"
                    f"<PackedPolicySize>0</PackedPolicySize>"
                    f"</AssumeRoleResult>",
                    ns="sts")

    if action == "AssumeRoleWithWebIdentity":
        role_arn = _p(params, "RoleArn")
        session = _p(params, "RoleSessionName", "session")
        duration = int(_p(params, "DurationSeconds") or 3600)
        access_key = _gen_session_access_key()
        secret_key = _gen_secret()
        session_token = _gen_session_token()
        assumed_arn = role_arn.replace(":role/", ":assumed-role/", 1)
        if not assumed_arn.endswith(f"/{session}"):
            assumed_arn = f"{assumed_arn}/{session}"
        role_id = "AROA" + new_uuid().replace("-", "")[:17].upper()
        provider = _p(params, "ProviderId") or "sts.amazonaws.com"
        assumed_user_id = f"{role_id}:{session}"
        _assumed_role_sessions[access_key] = {"arn": assumed_arn, "user_id": assumed_user_id}
        if use_json:
            return json_response({
                "Credentials": {"AccessKeyId": access_key, "SecretAccessKey": secret_key, "SessionToken": session_token, "Expiration": time.time() + duration},
                "AssumedRoleUser": {"AssumedRoleId": assumed_user_id, "Arn": assumed_arn},
                "SubjectFromWebIdentityToken": "test-subject",
                "Audience": "sts.amazonaws.com",
                "Provider": provider,
            })
        return _xml(200, "AssumeRoleWithWebIdentityResponse",
                    f"<AssumeRoleWithWebIdentityResult>"
                    f"<Credentials>"
                    f"<AccessKeyId>{access_key}</AccessKeyId>"
                    f"<SecretAccessKey>{secret_key}</SecretAccessKey>"
                    f"<SessionToken>{session_token}</SessionToken>"
                    f"<Expiration>{_future(duration)}</Expiration>"
                    f"</Credentials>"
                    f"<AssumedRoleUser>"
                    f"<AssumedRoleId>{assumed_user_id}</AssumedRoleId>"
                    f"<Arn>{assumed_arn}</Arn>"
                    f"</AssumedRoleUser>"
                    f"<SubjectFromWebIdentityToken>test-subject</SubjectFromWebIdentityToken>"
                    f"<Audience>sts.amazonaws.com</Audience>"
                    f"<Provider>{provider}</Provider>"
                    f"</AssumeRoleWithWebIdentityResult>",
                    ns="sts")

    if action == "GetSessionToken":
        duration = int(_p(params, "DurationSeconds") or 43200)
        expiration = _future(duration)
        access_key = _gen_session_access_key()
        secret_key = _gen_secret()
        session_token = _gen_session_token()
        if use_json:
            return json_response({
                "Credentials": {"AccessKeyId": access_key, "SecretAccessKey": secret_key, "SessionToken": session_token, "Expiration": time.time() + duration},
            })
        return _xml(200, "GetSessionTokenResponse",
                    f"<GetSessionTokenResult>"
                    f"<Credentials>"
                    f"<AccessKeyId>{access_key}</AccessKeyId>"
                    f"<SecretAccessKey>{secret_key}</SecretAccessKey>"
                    f"<SessionToken>{session_token}</SessionToken>"
                    f"<Expiration>{expiration}</Expiration>"
                    f"</Credentials>"
                    f"</GetSessionTokenResult>",
                    ns="sts")

    if action == "GetAccessKeyInfo":
        if use_json:
            return json_response({"Account": get_account_id()})
        return _xml(200, "GetAccessKeyInfoResponse",
                    f"<GetAccessKeyInfoResult>"
                    f"<Account>{get_account_id()}</Account>"
                    f"</GetAccessKeyInfoResult>",
                    ns="sts")

    return _error(400, "InvalidAction", f"Unknown STS action: {action}", ns="sts")
