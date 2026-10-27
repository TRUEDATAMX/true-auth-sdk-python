
# TrueAuth Library

TrueAuth is a Python library for generating and validating JSON Web Tokens (JWT) for secure service-to-service communication. It simplifies token creation and validation using environment variables for configuration.

## Features

- **JWT Generation**: Generate signed JWTs with a shared secret.
- **Token Validation**: Validate tokens against a configured authentication endpoint.
- **Configurable via Environment Variables**: Easily integrate into different environments using environment variables.

---

## Installation

To use this library, you need to have Python 3.x and the required dependencies installed. Install dependencies using `pip`:

```bash
pip install pyjwt requests httpx
```

---

## Environment Variables

The library relies on the following environment variables for configuration:

| Variable Name                 | Description                                           | Required |
|-------------------------------|-------------------------------------------------------|----------|
| `TRUE_SHARED_SECRET`          | Shared secret key used for signing JWTs.             | Yes      |
| `TRUE_AUTHENTICATION_ENDPOINT`| Endpoint URL for validating tokens.                  | No       |
| `TRUE_SERVICE_NAME`           | Unique service name to identify the token issuer.    | Yes      |

---

## Usage

### Initialization

Create an instance of the `TrueAuth` class:

```python
from trueauth import TrueAuth

auth = TrueAuth()
```

### Generating a Token

Use the `token` method to generate a JWT for a specified audience:

```python
audience = "example-audience"
token = auth.token(audience)
print(f"Generated Token: {token}")
```

### Validating a Token

To validate a token, use the `validate` method. It returns the endpoint's response when the token is valid and `False` when the endpoint rejects it (400 or 401):

```python
result = auth.validate(token)
if not result:
    ...  # reject the request
```

In async code (FastAPI, Starlette middlewares), use `validate_async`, which makes the same call with `httpx` and doesn't block the event loop:

```python
result = await auth.validate_async(token)
```

Both methods remember a token that passed until its `exp` claim (60 seconds if it has none), so a caller that sends the same token on every request only triggers one call to the endpoint. Rejected tokens are never cached. Any other status from the endpoint raises an exception, and a network error returns `None`.

### Validating Custom Headers

If you already have headers, you can validate them directly:

```python
headers = {
    "Authorization": f"Bearer {token}",
    "Service": "example-service-name"
}
validation_result = auth.validate_headers(headers)
print(f"Header Validation Result: {validation_result}")
```

---

## Error Handling

The library raises `RuntimeError` for critical configuration errors, such as missing shared secrets or service names. Validation returns `False` for a token the endpoint rejects (400 or 401), raises for any other unexpected status and returns `None` when the endpoint can't be reached.

---

## Example Workflow

1. **Set Environment Variables**:
   ```bash
   export TRUE_SHARED_SECRET="your_shared_secret"
   export TRUE_AUTHENTICATION_ENDPOINT="https://auth.example.com/validate"
   export TRUE_SERVICE_NAME="my-service"
   ```

2. **Generate a Token**:
   ```python
   token = auth.token("target-service")
   print(f"Token: {token}")
   ```

3. **Validate a Token**:
   ```python
   result = auth.validate(token)
   print("Validation Result:", result)
   ```

---

## Dependencies

- **[PyJWT](https://pyjwt.readthedocs.io/)**: For JWT generation and decoding.
- **[Requests](https://docs.python-requests.org/)**: For making HTTP requests.
- **[HTTPX](https://www.python-httpx.org/)**: For the async validation call.

---

## Tests

```bash
pip install -r requirements.txt pytest
pytest
```

---

## Limitations

- The library assumes that the shared secret and service name are securely stored in environment variables.
- It does not include robust retry mechanisms for network requests.
- The token expiration is hardcoded to 5 minutes and cannot be dynamically configured.

---

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a clear description of your changes.

---

## License

This library is available under the MIT License. See the LICENSE file for more details.

---

## Contact

For questions or issues, please open an issue on the GitHub repository.
