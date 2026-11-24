import os
import jwt
import copy
import math
import time
import datetime
import threading
import httpx
import requests

TOKEN_TYPE = "JWT"
ALGORITHM = "HS256"
VALIDATION_TIMEOUT_SECONDS = 10
# A token with no exp claim is trusted for this long before it's validated again
DEFAULT_CACHE_SECONDS = 60
# A token is validated again after this long even if its exp is later, so a revoked
# token or a rotated secret takes effect within minutes
MAX_CACHE_SECONDS = 300
# Upper bound so a stream of distinct tokens can't grow the cache without limit
MAX_CACHED_TOKENS = 1024


class TrueAuthUnavailable(Exception):
    """The validation endpoint couldn't give an answer: it was unreachable, timed out,
    answered an unexpected status or sent a 200 without JSON. It says nothing about the
    token itself, so callers can answer 503 instead of 401."""


class TrueAuth:

    def __init__(self, shared_secret=None, endpoint=None, service_name=None) -> None:
        # shared_secret: use provided value or fall back to env var
        if shared_secret is None:
            try:
                shared_secret = os.environ['TRUE_SHARED_SECRET']
            except Exception as e:
                print("No shared secret was found. Unable to sign tokens.")
                shared_secret = None

        # endpoint: use provided value or fall back to env var
        if endpoint is None:
            try:
                endpoint = os.environ['TRUE_AUTHENTICATION_ENDPOINT']
            except Exception as e:
                endpoint = None
                print("No registered authentication endpoint found. Unable to validate tokens.")

        # service_name: use provided value or fall back to env var
        if service_name is None:
            try:
                service_name = os.environ['TRUE_SERVICE_NAME']
            except Exception as e:
                print(e)
                raise RuntimeError("Must declare service name.", e)

        self.shared_secret_ = shared_secret
        self.endpoint_ = endpoint
        self.service_name_ = service_name
        # (endpoint, service name, token) -> (validation result, unix time it stops being trusted)
        self.validated_ = {}
        self.validated_lock_ = threading.Lock()

    def token(self, audience):
        if not self.shared_secret_:
            raise RuntimeError("Shared secret not available.")
        headers = {
            "alg": ALGORITHM,
            "typ": TOKEN_TYPE,
            "kid": self.service_name_
        }
        payload = {
            "iss": self.service_name_,
            "aud": audience,
            "iat": datetime.datetime.utcnow(),
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=5)
        }
        return jwt.encode(payload, self.shared_secret_, algorithm=ALGORITHM, headers=headers)

    def validate(self, token):
        """Return the endpoint's response for a valid token and False for one it rejects.

        A token that passed is remembered for a few minutes at most (never past its
        exp), so repeated calls with the same token don't hit the endpoint again.
        As before, it returns None when the endpoint can't be reached or answers 200
        without JSON, and raises for any other unexpected status, so treat any falsy
        result as a rejection.
        """
        cached = self._cached_validation(token)
        if cached is not None:
            return cached
        result = self.validate_headers(self._validation_headers(token))
        self._remember_validation(token, result)
        return result

    async def validate_async(self, token):
        """Same as validate, without blocking the event loop.

        Unlike validate, it raises TrueAuthUnavailable when the endpoint can't give an
        answer, so callers can tell an outage from a rejected token.
        """
        cached = self._cached_validation(token)
        if cached is not None:
            return cached
        headers = self._validation_headers(token)
        try:
            async with httpx.AsyncClient(timeout=VALIDATION_TIMEOUT_SECONDS) as client:
                response = await client.get(self.endpoint_, headers=headers)
        except httpx.HTTPError as e:
            raise TrueAuthUnavailable(f"Could not reach the validation endpoint: {e}") from e
        result = self._validation_result(response.status_code, response.json)
        self._remember_validation(token, result)
        return result

    def validate_headers(self, headers):
        try:
            response = requests.get(self.endpoint_, headers=headers, timeout=VALIDATION_TIMEOUT_SECONDS)
        except requests.exceptions.RequestException as e:
            print("An error occurred while making the request:", e)
            return None
        if response.status_code == 200:
            # Kept from earlier versions: a 200 that isn't JSON returns None
            try:
                return response.json()
            except ValueError as e:
                print("The validation endpoint answered 200 without JSON:", e)
                return None
        return self._validation_result(response.status_code, response.json)

    def _validation_headers(self, token):
        if not self.endpoint_:
            raise RuntimeError("Validation endpoint not available.")
        return {
            "Authorization": f"Bearer {token}",
            "Service": self.service_name_
        }

    @staticmethod
    def _validation_result(status_code, read_json):
        if status_code == 200:
            try:
                return read_json()
            except ValueError as e:
                raise TrueAuthUnavailable("The validation endpoint answered 200 without JSON") from e
        # The endpoint answers 401 for a bad or expired token and 400 for a malformed one
        if status_code in (400, 401):
            return False
        raise TrueAuthUnavailable(f"Unexpected status code {status_code}")

    def _cache_key(self, token):
        # The same token can be valid for one service and not another
        return (self.endpoint_, self.service_name_, token)

    def _cached_validation(self, token):
        key = self._cache_key(token)
        with self.validated_lock_:
            entry = self.validated_.get(key)
            if entry is None:
                return None
            result, trusted_until = entry
            if time.time() >= trusted_until:
                del self.validated_[key]
                return None
        # A copy, so a caller that changes the result doesn't change it for the next one
        return copy.deepcopy(result)

    def _remember_validation(self, token, result):
        if not result:
            return
        now = time.time()
        trusted_until = self._expiry(token, now)
        if trusted_until <= now:
            return
        key = self._cache_key(token)
        with self.validated_lock_:
            if key not in self.validated_ and len(self.validated_) >= MAX_CACHED_TOKENS:
                for cached_key in [k for k, (_, until) in self.validated_.items() if until <= now]:
                    del self.validated_[cached_key]
                if len(self.validated_) >= MAX_CACHED_TOKENS:
                    # Still full: drop the oldest entry
                    del self.validated_[next(iter(self.validated_))]
            self.validated_[key] = (copy.deepcopy(result), trusted_until)

    @staticmethod
    def _expiry(token, now):
        # Only read after the endpoint accepted the token, so the claims can be trusted
        default = now + DEFAULT_CACHE_SECONDS
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return default
        exp = claims.get("exp")
        if isinstance(exp, bool) or not isinstance(exp, (int, float)) or not math.isfinite(exp):
            return default
        return min(float(exp), now + MAX_CACHE_SECONDS)
