import os
import jwt
import datetime
import requests

TOKEN_TYPE = "JWT"
ALGORITHM = "HS256"

class TrueAuth:

    def __init__(self) -> None:
        try:
            shared_secret = os.environ['TRUE_SHARED_SECRET']
        except Exception as e:
            print("No shared secret was found. Unable to sign tokens.")
            shared_secret = None
        try:
            endpoint = os.environ['TRUE_AUTHENTICATION_ENDPOINT']
        except Exception as e:
            endpoint = None
            print("No registered authentication endpoint found. Unable to validate tokens.")
        
        try:
            service_name = os.environ['TRUE_SERVICE_NAME']
        except Exception as e:
            print(e)
            raise RuntimeError("Must declare service name.", e)

        self.shared_secret_ = shared_secret
        self.endpoint_ = endpoint
        self.service_name_ = service_name

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
        if not self.endpoint_:
            raise RuntimeError("Validation endpoint not available.")
        headers = {
            "Authorization": f"Bearer {token}",
            "Service": self.service_name_
        }
        return self.validate_headers(headers)

    def validate_headers(self, headers):
        try:
            response = requests.get(self.endpoint_, headers=headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                raise Exception(f"Authentication failed: {response.json()}")
            elif response.status_code == 400:
                raise Exception(f"Bad Request: {response.json()}")
            else:
                raise Exception(f"Unexpected status code {response.status_code}")
        except requests.exceptions.RequestException as e:
            print("An error occurred while making the request:", e)
