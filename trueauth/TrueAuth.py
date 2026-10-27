import os
import jwt
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
# Upper bound so a stream of distinct tokens can't grow the cache without limit
MAX_CACHED_TOKENS = 1024

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
        # token -> (validation result, unix time it stops being trusted)
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

        A token that passed is remembered until it expires, so repeated calls with
        the same token don't hit the endpoint again.
        """
        cached = self._cached_validation(token)
        if cached is not None:
            return cached
        result = self.validate_headers(self._validation_headers(token))
        self._remember_validation(token, result)
        return result

    async def validate_async(self, token):
        """Same as validate, without blocking the event loop."""
        cached = self._cached_validation(token)
        if cached is not None:
            return cached
        headers = self._validation_headers(token)
        try:
            async with httpx.AsyncClient(timeout=VALIDATION_TIMEOUT_SECONDS) as client:
                response = await client.get(self.endpoint_, headers=headers)
        except httpx.HTTPError as e:
            print("An error occurred while making the request:", e)
            return None
        result = self._validation_result(response.status_code, response.json)
        self._remember_validation(token, result)
        return result

    def validate_headers(self, headers):
        try:
            response = requests.get(self.endpoint_, headers=headers, timeout=VALIDATION_TIMEOUT_SECONDS)
        except requests.exceptions.RequestException as e:
            print("An error occurred while making the request:", e)
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
            return read_json()
        # The endpoint answers 401 for a bad or expired token and 400 for a malformed one
        if status_code in (400, 401):
            return False
        raise Exception(f"Unexpected status code {status_code}")

    def _cached_validation(self, token):
        with self.validated_lock_:
            entry = self.validated_.get(token)
            if entry is None:
                return None
            result, trusted_until = entry
            if time.time() >= trusted_until:
                del self.validated_[token]
                return None
            return result

    def _remember_validation(self, token, result):
        if not result:
            return
        trusted_until = self._expiry(token)
        if trusted_until <= time.time():
            return
        with self.validated_lock_:
            if len(self.validated_) >= MAX_CACHED_TOKENS:
                now = time.time()
                for cached_token in [t for t, (_, until) in self.validated_.items() if until <= now]:
                    del self.validated_[cached_token]
            if len(self.validated_) >= MAX_CACHED_TOKENS:
                # Still full: drop the oldest entry
                del self.validated_[next(iter(self.validated_))]
            self.validated_[token] = (result, trusted_until)

    @staticmethod
    def _expiry(token):
        # Only read after the endpoint accepted the token, so the claims can be trusted
        try:
            claims = jwt.decode(token, options={"verify_signature": False})
        except jwt.InvalidTokenError:
            return time.time() + DEFAULT_CACHE_SECONDS
        exp = claims.get("exp")
        if isinstance(exp, (int, float)):
            return float(exp)
        return time.time() + DEFAULT_CACHE_SECONDS
