import asyncio
import time

import httpx
import jwt
import pytest
import requests

from trueauth import TrueAuth as trueauth_module
from trueauth.TrueAuth import TrueAuth, TrueAuthUnavailable

ENDPOINT = "https://auth.example.com/m2m/auth/"


def make_auth():
    return TrueAuth(shared_secret="secret", endpoint=ENDPOINT, service_name="caller-service")


def make_token(exp_in_seconds=300, exp=None):
    claims = {"iss": "caller-service", "aud": "target"}
    if exp is not None:
        claims["exp"] = exp
    elif exp_in_seconds is not None:
        claims["exp"] = int(time.time()) + exp_in_seconds
    return jwt.encode(claims, "secret", algorithm="HS256")


def cached_tokens(auth):
    return [token for (_, _, token) in auth.validated_]


class FakeResponse:
    def __init__(self, status_code, body=None, not_json=False):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self._not_json = not_json

    def json(self):
        if self._not_json:
            raise requests.exceptions.JSONDecodeError("Expecting value", "<html>", 0)
        return self._body


@pytest.fixture
def sync_endpoint(monkeypatch):
    """Answer requests.get with the queued responses, recording each call."""
    calls = []
    responses = []

    def fake_get(url, headers=None, timeout=None):
        calls.append({"url": url, "headers": headers, "timeout": timeout})
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(trueauth_module.requests, "get", fake_get)
    return calls, responses


@pytest.fixture
def async_endpoint(monkeypatch):
    """Route httpx.AsyncClient to a handler that serves the queued responses."""
    calls = []
    responses = []
    real_client = httpx.AsyncClient

    def handler(request):
        calls.append(request)
        response = responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(
        trueauth_module.httpx,
        "AsyncClient",
        lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs),
    )
    return calls, responses


# ---------------------------------------------------------------------------
# validate (sync)
# ---------------------------------------------------------------------------

def test_validate_returns_the_endpoint_response_for_a_good_token(sync_endpoint):
    calls, responses = sync_endpoint
    responses.append(FakeResponse(200, {"iss": "caller-service"}))
    token = make_token()

    assert make_auth().validate(token) == {"iss": "caller-service"}
    assert calls[0]["headers"] == {"Authorization": f"Bearer {token}", "Service": "caller-service"}
    assert calls[0]["timeout"] is not None


@pytest.mark.parametrize("status_code", [400, 401])
def test_validate_returns_false_when_the_endpoint_rejects_the_token(sync_endpoint, status_code):
    _, responses = sync_endpoint
    responses.append(FakeResponse(status_code, {"detail": "bad token"}))

    assert make_auth().validate(make_token()) is False


def test_validate_raises_on_an_unexpected_status(sync_endpoint):
    _, responses = sync_endpoint
    responses.append(FakeResponse(503))

    # TrueAuthUnavailable is an Exception, so callers that caught Exception still do
    with pytest.raises(TrueAuthUnavailable, match="Unexpected status code 503"):
        make_auth().validate(make_token())


def test_validate_returns_none_for_a_200_without_json(sync_endpoint):
    _, responses = sync_endpoint
    responses.append(FakeResponse(200, not_json=True))

    assert make_auth().validate(make_token()) is None


def test_validate_returns_none_when_the_endpoint_is_unreachable(sync_endpoint):
    _, responses = sync_endpoint
    responses.append(requests.exceptions.ConnectionError("down"))

    assert make_auth().validate(make_token()) is None


def test_validate_requires_an_endpoint():
    auth = TrueAuth(shared_secret="secret", endpoint=None, service_name="caller-service")
    auth.endpoint_ = None

    with pytest.raises(RuntimeError):
        auth.validate(make_token())


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def test_a_valid_token_is_checked_once_until_it_expires(sync_endpoint):
    calls, responses = sync_endpoint
    responses.append(FakeResponse(200, {"ok": True}))
    auth = make_auth()
    token = make_token()

    assert auth.validate(token) == {"ok": True}
    assert auth.validate(token) == {"ok": True}
    assert len(calls) == 1


def test_a_rejected_token_is_not_cached(sync_endpoint):
    calls, responses = sync_endpoint
    responses.extend([FakeResponse(401), FakeResponse(401)])
    auth = make_auth()
    token = make_token()

    assert auth.validate(token) is False
    assert auth.validate(token) is False
    assert len(calls) == 2


def test_an_expired_cache_entry_is_validated_again(sync_endpoint, monkeypatch):
    calls, responses = sync_endpoint
    responses.extend([FakeResponse(200, {"ok": True}), FakeResponse(401)])
    auth = make_auth()
    token = make_token(exp_in_seconds=60)

    assert auth.validate(token) == {"ok": True}
    later = time.time() + 120
    monkeypatch.setattr(trueauth_module.time, "time", lambda: later)

    assert auth.validate(token) is False
    assert len(calls) == 2


def test_a_token_without_exp_is_trusted_for_the_default_window(sync_endpoint, monkeypatch):
    calls, responses = sync_endpoint
    responses.extend([FakeResponse(200, {"ok": True}), FakeResponse(200, {"ok": True})])
    auth = make_auth()
    token = make_token(exp_in_seconds=None)

    auth.validate(token)
    auth.validate(token)
    assert len(calls) == 1

    later = time.time() + trueauth_module.DEFAULT_CACHE_SECONDS + 1
    monkeypatch.setattr(trueauth_module.time, "time", lambda: later)
    auth.validate(token)
    assert len(calls) == 2


def test_the_cache_never_holds_more_than_the_limit(sync_endpoint, monkeypatch):
    _, responses = sync_endpoint
    monkeypatch.setattr(trueauth_module, "MAX_CACHED_TOKENS", 3)
    auth = make_auth()
    tokens = [make_token(exp_in_seconds=300 + i) for i in range(5)]
    responses.extend(FakeResponse(200, {"ok": True}) for _ in tokens)

    for token in tokens:
        auth.validate(token)

    assert len(auth.validated_) == 3
    assert tokens[0] not in cached_tokens(auth)
    assert tokens[-1] in cached_tokens(auth)


def test_caching_a_token_again_when_full_keeps_the_others(sync_endpoint, monkeypatch):
    _, responses = sync_endpoint
    monkeypatch.setattr(trueauth_module, "MAX_CACHED_TOKENS", 2)
    auth = make_auth()
    first, second = make_token(exp_in_seconds=300), make_token(exp_in_seconds=301)
    responses.extend(FakeResponse(200, {"ok": True}) for _ in range(2))
    auth.validate(first)
    auth.validate(second)

    auth._remember_validation(second, {"ok": True})

    assert cached_tokens(auth) == [first, second]


def test_a_far_future_exp_is_trusted_for_the_maximum_window_only(sync_endpoint, monkeypatch):
    calls, responses = sync_endpoint
    responses.extend([FakeResponse(200, {"ok": True}), FakeResponse(401)])
    auth = make_auth()
    token = make_token(exp_in_seconds=10 * 365 * 24 * 3600)

    assert auth.validate(token) == {"ok": True}
    later = time.time() + trueauth_module.MAX_CACHE_SECONDS + 1
    monkeypatch.setattr(trueauth_module.time, "time", lambda: later)

    assert auth.validate(token) is False
    assert len(calls) == 2


def test_a_non_finite_exp_gets_the_default_window(sync_endpoint, monkeypatch):
    calls, responses = sync_endpoint
    responses.extend([FakeResponse(200, {"ok": True}), FakeResponse(200, {"ok": True})])
    auth = make_auth()
    token = make_token(exp=float("nan"))

    auth.validate(token)
    later = time.time() + trueauth_module.DEFAULT_CACHE_SECONDS + 1
    monkeypatch.setattr(trueauth_module.time, "time", lambda: later)
    auth.validate(token)

    assert len(calls) == 2


def test_the_cache_is_per_service(sync_endpoint):
    calls, responses = sync_endpoint
    responses.extend([FakeResponse(200, {"ok": True}), FakeResponse(401)])
    auth = make_auth()
    token = make_token()

    assert auth.validate(token) == {"ok": True}
    auth.service_name_ = "another-service"

    assert auth.validate(token) is False
    assert len(calls) == 2


def test_changing_a_returned_result_does_not_change_the_cache(sync_endpoint):
    _, responses = sync_endpoint
    responses.append(FakeResponse(200, {"iss": "caller-service"}))
    auth = make_auth()
    token = make_token()

    auth.validate(token)["iss"] = "someone-else"
    cached = auth.validate(token)
    cached["iss"] = "someone-else"

    assert auth.validate(token) == {"iss": "caller-service"}


# ---------------------------------------------------------------------------
# validate_async
# ---------------------------------------------------------------------------

def test_validate_async_returns_the_endpoint_response_for_a_good_token(async_endpoint):
    calls, responses = async_endpoint
    responses.append(httpx.Response(200, json={"iss": "caller-service"}))
    token = make_token()

    assert asyncio.run(make_auth().validate_async(token)) == {"iss": "caller-service"}
    assert str(calls[0].url) == ENDPOINT
    assert calls[0].headers["Authorization"] == f"Bearer {token}"
    assert calls[0].headers["Service"] == "caller-service"


@pytest.mark.parametrize("status_code", [400, 401])
def test_validate_async_returns_false_when_the_endpoint_rejects_the_token(async_endpoint, status_code):
    _, responses = async_endpoint
    responses.append(httpx.Response(status_code, json={"detail": "bad token"}))

    assert asyncio.run(make_auth().validate_async(make_token())) is False


def test_validate_async_raises_unavailable_on_an_unexpected_status(async_endpoint):
    _, responses = async_endpoint
    responses.append(httpx.Response(500))

    with pytest.raises(TrueAuthUnavailable, match="Unexpected status code 500"):
        asyncio.run(make_auth().validate_async(make_token()))


@pytest.mark.parametrize("error", [httpx.ConnectError("down"), httpx.ReadTimeout("slow")])
def test_validate_async_raises_unavailable_when_the_endpoint_is_unreachable(async_endpoint, error):
    _, responses = async_endpoint
    responses.append(error)

    with pytest.raises(TrueAuthUnavailable):
        asyncio.run(make_auth().validate_async(make_token()))


def test_validate_async_raises_unavailable_for_a_200_without_json(async_endpoint):
    _, responses = async_endpoint
    responses.append(httpx.Response(200, text="<html>maintenance</html>"))

    with pytest.raises(TrueAuthUnavailable):
        asyncio.run(make_auth().validate_async(make_token()))


def test_an_outage_is_not_cached(async_endpoint):
    calls, responses = async_endpoint
    responses.extend([httpx.ConnectError("down"), httpx.Response(200, json={"ok": True})])
    auth = make_auth()
    token = make_token()

    with pytest.raises(TrueAuthUnavailable):
        asyncio.run(auth.validate_async(token))
    assert asyncio.run(auth.validate_async(token)) == {"ok": True}
    assert len(calls) == 2


def test_validate_async_shares_the_cache_with_validate(async_endpoint, sync_endpoint):
    async_calls, async_responses = async_endpoint
    sync_calls, _ = sync_endpoint
    async_responses.append(httpx.Response(200, json={"ok": True}))
    auth = make_auth()
    token = make_token()

    assert asyncio.run(auth.validate_async(token)) == {"ok": True}
    assert asyncio.run(auth.validate_async(token)) == {"ok": True}
    assert auth.validate(token) == {"ok": True}
    assert len(async_calls) == 1
    assert sync_calls == []
