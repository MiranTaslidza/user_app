import hashlib
import json
import secrets

from django.core import signing
from django.utils.crypto import constant_time_compare, salted_hmac

# Posebna namjena potpisa: potvrda deaktivacije računa.
TOKEN_SALT = 'users.account_deactivation'

# Link vrijedi 15 minuta.
TOKEN_MAX_AGE = 15 * 60

def get_account_state(user):
    # Vežemo zahtjev za trenutni račun, email, lozinku i aktivnost.
    # Promjena tih podataka poništava prethodno izdani token.
    state = json.dumps([
        str(user.pk),
        user.email,
        user.password,
        user.is_active,
    ])

    # U token ne stavljamo lozinku niti njen spremljeni hash.
    # Stavljamo samo poseban potpis ovog skupa podataka.
    return salted_hmac(
        'users.account_deactivation.state',
        state,
        algorithm='sha256',
    ).hexdigest()

def prepare_account_deactivation_token(profile):
    user = profile.user

    # Zahtjev pripremamo samo za aktivan, nedeaktiviran račun.
    if not user.is_active or profile.deactivated_at is not None:
        raise ValueError('Account is not eligible for deactivation.')

    # Nasumična vrijednost osigurava različit token za svaki zahtjev.
    payload = {
        'user_id': str(user.pk),
        'nonce': secrets.token_urlsafe(32),
        'account_state': get_account_state(user),
    }

    # Django dodaje vremensku oznaku i potpis.
    token = signing.dumps(payload, salt=TOKEN_SALT)

    # Za bazu pripremamo samo hash cijelog tokena.
    profile.deactivation_token_hash = hashlib.sha256(
        token.encode()
    ).hexdigest()

    # Originalni token vraćamo radi pravljenja email linka.
    return token

def check_account_deactivation_token(profile, token):
    user = profile.user

    if not isinstance(token, str) or not token or len(token) > 4096:
        return False

    if not user.is_active or profile.deactivated_at is not None:
        return False

    if not profile.deactivation_token_hash:
        return False

    # Token mora odgovarati posljednjem spremljenom zahtjevu.
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    if not constant_time_compare(
        profile.deactivation_token_hash,
        token_hash,
    ):
        return False

    # Provjeravamo potpis i rok važenja.
    try:
        payload = signing.loads(
            token,
            salt=TOKEN_SALT,
            max_age=TOKEN_MAX_AGE,
        )
    except signing.BadSignature:
        return False

    if not isinstance(payload, dict):
        return False

    if payload.get('user_id') != str(user.pk):
        return False

    # Email, lozinka i aktivnost računa moraju još odgovarati zahtjevu.
    return constant_time_compare(
        payload.get('account_state', ''),
        get_account_state(user),
    )

