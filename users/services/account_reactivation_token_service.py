import json
import secrets

from django.core import signing
from django.utils.crypto import constant_time_compare, salted_hmac

# Ovaj potpis koristimo isključivo za ponovno aktiviranje računa.
TOKEN_SALT = 'users.account_reactivation'

# Aktivacijski link vrijedi 15 minuta.
TOKEN_MAX_AGE = 15 * 60

def get_reactivation_state(profile):
    user = profile.user

    # Vežemo token za račun i njegovu konkretnu deaktivaciju.
    state = json.dumps([
        str(user.pk),
        user.email,
        user.password,
        user.is_active,
        profile.deactivated_at.isoformat(),
    ])

    # U token ne spremamo lozinku ni njen spremljeni hash.
    return salted_hmac(
        'users.account_reactivation.state',
        state,
        algorithm='sha256',
    ).hexdigest()

def prepare_account_reactivation_token(profile):
    user = profile.user

    # Aktivaciju nudimo samo neaktivnom računu s datumom deaktivacije.
    if user.is_active or profile.deactivated_at is None:
        raise ValueError('Account is not eligible for reactivation.')

    payload = {
        'user_id': str(user.pk),
        'nonce': secrets.token_urlsafe(32),
        'account_state': get_reactivation_state(profile),
    }

    # Django dodaje vremensku oznaku i štiti podatke potpisom.
    return signing.dumps(payload, salt=TOKEN_SALT)

def check_account_reactivation_token(profile, token):
    user = profile.user

    if not isinstance(token, str) or not token or len(token) > 4096:
        return False

    # Već aktiviran račun ne može ponovo koristiti aktivacijski token.
    if user.is_active or profile.deactivated_at is None:
        return False

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

    # Podaci računa i datum deaktivacije moraju ostati isti.
    return constant_time_compare(
        payload.get('account_state', ''),
        get_reactivation_state(profile),
    )

