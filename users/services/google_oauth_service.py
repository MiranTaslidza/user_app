
import requests
import secrets
from django.conf import settings
from google.auth.transport.requests import Request as GoogleRequest
from google.oauth2 import id_token

# Google OAuth endpoint na koji šaljemo korisnika
GOOGLE_AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"

# Google endpoint koji koristimo za razmjenu authorization code-a
# za access token
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"

# Google endpoint sa kojeg uzimamo podatke o prijavljenom korisniku
GOOGLE_USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo"

def get_google_authorization_url(request):
    """
    Kreira URL na koji ćemo poslati korisnika
    kada klikne na "Login with Google".
    """

    state = secrets.token_urlsafe(32)
    request.session['google_oauth_state'] = state
    
    nonce = secrets.token_urlsafe(32)
    request.session['google_oauth_nonce'] = nonce

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "state": state,
        "nonce": nonce,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
    }

    from urllib.parse import urlencode

    return f"{GOOGLE_AUTHORIZATION_URL}?{urlencode(params)}"
def exchange_code_for_token(code):
    """
    Prima authorization code koji je Google poslao
    našem callback view-u.

    Taj code zatim mijenjamo za Google access token.
    """

    data = {
        "code": code,

        "client_id": settings.GOOGLE_CLIENT_ID,

        "client_secret": settings.GOOGLE_CLIENT_SECRET,

        "redirect_uri": settings.GOOGLE_REDIRECT_URI,

        "grant_type": "authorization_code",
    }

    response = requests.post(
        GOOGLE_TOKEN_URL,
        data=data,
        timeout=10,
    )

    response.raise_for_status()

    return response.json()

def get_google_user_info(access_token):
    """
    Koristi Google access token da dobije podatke
    o trenutno prijavljenom Google korisniku.
    """

    headers = {
        "Authorization": f"Bearer {access_token}",
    }

    response = requests.get(
        GOOGLE_USERINFO_URL,
        headers=headers,
        timeout=10,
    )

    response.raise_for_status()

    return response.json()

def verify_google_id_token(raw_id_token, expected_nonce):
    transport = GoogleRequest()

    def google_request(*args, **kwargs):
        kwargs['timeout'] = 10
        return transport(*args, **kwargs)

    google_user = id_token.verify_oauth2_token(
        raw_id_token,
        google_request,
        settings.GOOGLE_CLIENT_ID,
    )

    received_nonce = google_user.get('nonce')

    if (
        not expected_nonce
        or not isinstance(received_nonce, str)
        or not secrets.compare_digest(received_nonce, expected_nonce)
    ):
        raise ValueError('Invalid Google nonce.')

    return google_user

