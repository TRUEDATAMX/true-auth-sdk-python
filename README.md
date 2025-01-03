
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
pip install pyjwt requests
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

To validate a token, use the `validate` method:

```python
is_valid = auth.validate(token)
print(f"Validation Result: {is_valid}")
```

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

The library raises `RuntimeError` for critical configuration errors, such as missing shared secrets or service names. HTTP errors during validation are also reported with descriptive messages.

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
