from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from .middleware import JWTAuthBase


class JWTAuthentication(BaseAuthentication, JWTAuthBase):
    """
    Django REST Framework authentication class for authenticating users using JWT
    Authentication headers
    """

    def authenticate(self, request):
        """
        Process a Django request and authenticate users.

        If a JWT authentication header is detected and it is determined to be valid, the
        user object is returned.

        :param request: Django Request instance
        """
        user = self.process_base(request)
        if not user:
            raise AuthenticationFailed()
        return (user, None)
