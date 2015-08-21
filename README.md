# Asymmetric JWT Authentication

[![build status](https://ci.gitlab.com/projects/6313/status.png?ref=master)](https://ci.gitlab.com/projects/6313?ref=master)

## What?

This is an library designed to handle authentication in *server-to-server* API requests. It accomplishes this using RSA public / private key pairs.

## Why?

The standard pattern of using username and password works well for user-to-server requests, but is lacking for server-to-server applications. In these scenarios, since the password doesn't need to be memorable by a user, we can use something far more secure: asymmetric key cryptography. This has the advantage that a password is never actually sent to the server.

## How?

A public / private key pair is generated by the client machine. The server machine is then supplied with the public key, which it can store in any method it likes. When this library is used with Django, it provides a model for storing public keys associated with built-in User objects. When a request is made, the client creates a JWT including several claims and signs it using it's private key. Upon receipt, the server verifies the claim to using the public key to ensure the issuer is legitimately who they claim to be.

The claim (issued by the client) includes components: the username of the user who is attempting authentication, the current unix timestamp, and a randomly generated nonce. For example:

```
{
    "username": "guido",
    "time": 1439216312,
    "nonce": "1"
}
```

The timestamp must be within ±20 seconds of the server time and the nonce must be unique within the given timestamp and user. In other words, if more than one request from a user is made within the same second, the nonce must change. Due to these two factors no token is usable more than once, thereby preventing replay attacks.

To make an authenticated request, the client must generate a JWT following the above format and include it as the HTTP Authorization header in the following format:

```
Authorization: JWT <my_token>
```

**Important note**: the claim is *not* encrypted, only signed. Additionally, the signature only prevents the claim from being tampered with or re-used. Every other part of the request is still vulnerable to tamper. Therefore, this is not a replacement for using SSL in the transport layer.

## Usage

Most all of the complexity described above is handled for you. Implementation is very easy.

## Django Server Installation:

1. Install the library: `pip install asymmetric_jwt_auth`
2. Add `asymmetric_jwt_auth` to the list of `INSTALLED_APPS` in `settings.py`
3. Add `asymmetric_jwt_auth.middleware.JWTAuthMiddleware` to the list of `MIDDLEWARE_CLASSES` in `settings.py`
4. Create the new models in your DB: `python manage.py migrate`

This creates a new relationship on the `django.contrib.auth.models.User` model: `User` now conains a one-to-many relationship to `asymmetric_jwt_auth.models.PublicKey`. Any number of public key's can be added to a user using the Django Admin site.

The middleware activated above will watch for incoming requests with a JWT authorization header and will attempt to authenticate it using saved public keys.

## Client Usage

Here's an example of making a request to a server using the JWT auth and the [requests](http://www.python-requests.org/) HTTP client library.

```
from asymmetric_jwt_auth import create_auth_header
import requests

auth = create_auth_header(
    username='crgwbr',        # This is the user to authenticate as on the server
    key_file='~/.ssh/id_rsa') # This is the local path to the file containing our RSA private key

r = requests.get('http://example.com/api/endpoint/', headers={
    'Authorization': auth
})
```

This method also supports using an encrypted private key.

```
from asymmetric_jwt_auth import create_auth_header
import requests

auth = create_auth_header(
    username='crgwbr',
    key_file='~/.ssh/id_rsa',
    key_password='somepassphrase')

r = requests.get('http://example.com/api/endpoint/', headers={
    'Authorization': auth
})
```
