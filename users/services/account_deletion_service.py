import json
import logging
import secrets

from datetime import timedelta
from smtplib import SMTPException

from django.contrib.auth import get_user_model
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.utils import timezone
from django.utils.crypto import constant_time_compare, salted_hmac
from django.contrib.auth.hashers import check_password
from django.contrib.sessions.models import Session
from .email_service import send_account_deleted_email
import errno
from pathlib import Path


from ..models.account_deletion_request_model import AccountDeletionRequest
from ..models.profile_model import Profile
from .email_service import send_account_deletion_code_email

logger = logging.getLogger(__name__)

CODE_LIFETIME = timedelta(minutes=10)
SEND_INTERVAL = timedelta(seconds=60)
SEND_WINDOW = timedelta(hours=1)
MAX_SEND_ATTEMPTS = 5
MAX_FAILED_ATTEMPTS = 5

def get_account_deletion_state(user):
    # Kod vežemo za trenutno stanje računa.
    # Nova prijava, promjena emaila ili lozinke poništavaju stari kod.
    state = json.dumps([
        str(user.pk),
        user.email,
        user.password,
        user.is_active,
        user.last_login.isoformat() if user.last_login else None,
    ])

    return salted_hmac(
        'users.account_deletion.state',
        state,
        algorithm='sha256',
    ).hexdigest()

def request_account_deletion_code(user):
    with transaction.atomic():
        # Prvo zaključavamo korisnika.
        account = get_user_model().objects.select_for_update().filter(
            pk=user.pk,
        ).first()

        if account is None:
            return False, 'This account is no longer available.'

        # Ne nastavljamo ako se lozinka promijenila od učitavanja korisnika.
        if not constant_time_compare(
            user.get_session_auth_hash(),
            account.get_session_auth_hash(),
        ):
            return False, 'Please sign in again before requesting account deletion.'

        account_deactivated = Profile.objects.filter(
            user_id=account.pk,
            deactivated_at__isnull=False,
        ).exists()

        if not account.is_active or account_deactivated:
            return False, 'This account is not available for deletion.'

        # Zatim zaključavamo postojeći zahtjev ili kreiramo prvi zapis.
        deletion_request, _ = (
            AccountDeletionRequest.objects.select_for_update().get_or_create(
                user=account,
            )
        )

        now = timezone.now()

        # Nakon jednog sata započinjemo novi period brojanja.
        if now >= deletion_request.send_window_started_at + SEND_WINDOW:
            deletion_request.send_window_started_at = now
            deletion_request.send_count = 0

        # Između pokušaja slanja mora proći najmanje 60 sekundi.
        if deletion_request.last_send_attempt_at is not None:
            next_allowed_at = (
                deletion_request.last_send_attempt_at + SEND_INTERVAL
            )

            if now < next_allowed_at:
                return False, 'Please wait at least 60 seconds between requests.'

        if deletion_request.send_count >= MAX_SEND_ATTEMPTS:
            return False, 'You have reached the hourly request limit. Please try again later.'

        # Brojimo pokušaj čak i ako SMTP slanje poslije ne uspije.
        deletion_request.send_count += 1
        deletion_request.last_send_attempt_at = now

        deletion_request.save(update_fields=[
            'send_window_started_at',
            'send_count',
            'last_send_attempt_at',
        ])

        try:
            # Unutrašnji blok omogućava poništavanje samo novog koda
            # ako slanje ne uspije, bez poništavanja brojača pokušaja.
            with transaction.atomic():
                # Kod uvijek ima šest cifara, uključujući početne nule.
                code = f'{secrets.randbelow(1_000_000):06d}'

                # U bazu ide hash, a originalni kod samo u email.
                code_hash = make_password(code)
                created_at = timezone.now()

                deletion_request.email = account.email
                deletion_request.code_hash = code_hash
                deletion_request.account_state = get_account_deletion_state(account)
                deletion_request.created_at = created_at
                deletion_request.expires_at = created_at + CODE_LIFETIME
                deletion_request.failed_attempts = 0

                deletion_request.save(update_fields=[
                    'email',
                    'code_hash',
                    'account_state',
                    'created_at',
                    'expires_at',
                    'failed_attempts',
                ])

                sent = send_account_deletion_code_email(
                    account,
                    code,
                    deletion_request.expires_at,
                )

                if sent != 1:
                    raise OSError('The mail backend did not confirm sending.')

        except (SMTPException, OSError):
            # Ne zapisujemo originalni kod u log.
            logger.exception(
                'Sending the account deletion code failed for user %s.',
                account.pk,
            )

            return False, (
                'The confirmation email could not be sent. '
                'Please wait before trying again.'
            )

        return True, 'A confirmation code has been sent to your email address.'

# Pomoćna provjera koju završni servis poziva pod zaključavanjem.
# Vraća poruku greške ili None ako je kod ispravan.
def _validate_account_deletion_code(account, deletion_request, code):
    if deletion_request.user_id != account.pk:
        return 'This deletion request is invalid.'

    if not account.is_active:
        return 'This account is not available for deletion.'

    account_deactivated = Profile.objects.filter(
        user_id=account.pk,
        deactivated_at__isnull=False,
    ).exists()

    if account_deactivated:
        return 'This account is not available for deletion.'

    if not deletion_request.code_hash:
        return 'Request a confirmation code before deleting your account.'

    # Kod ne smije biti istekao.
    if (
        deletion_request.expires_at is None
        or deletion_request.expires_at <= timezone.now()
    ):
        return 'The confirmation code has expired. Request a new code.'

    # Nakon pet pogrešnih pokušaja ovaj kod više ne prihvatamo.
    if deletion_request.failed_attempts >= MAX_FAILED_ATTEMPTS:
        return 'Too many incorrect attempts. Request a new code.'

    # Promjena podataka računa poništava prethodno izdani kod.
    if (
        deletion_request.email != account.email
        or not constant_time_compare(
            deletion_request.account_state,
            get_account_deletion_state(account),
        )
    ):
        deletion_request.code_hash = ''
        deletion_request.save(update_fields=['code_hash'])

        return 'Your account details have changed. Request a new code.'

    # Provjera oblika unosa postoji i ovdje, nezavisno od forme.
    if (
        not isinstance(code, str)
        or len(code) != 6
        or not code.isascii()
        or not code.isdigit()
    ):
        return 'Enter the six-digit confirmation code.'

    # Uspoređujemo unos sa spremljenim hashom.
    if not check_password(code, deletion_request.code_hash):
        deletion_request.failed_attempts += 1
        deletion_request.save(update_fields=['failed_attempts'])

        if deletion_request.failed_attempts >= MAX_FAILED_ATTEMPTS:
            return 'Too many incorrect attempts. Request a new code.'

        return 'The confirmation code is incorrect.'

    return None


# Provjerava kod i trajno briše račun u istoj transakciji.
def delete_account_with_code(user, code):
    with transaction.atomic():
        # Prvo zaključavamo korisnika.
        account = get_user_model().objects.select_for_update().filter(
            pk=user.pk,
        ).first()

        if account is None:
            return False, 'This account is no longer available.'

        # Zahtjev ne nastavlja ako je lozinka u međuvremenu promijenjena.
        if not constant_time_compare(
            user.get_session_auth_hash(),
            account.get_session_auth_hash(),
        ):
            return False, 'Please sign in again before deleting your account.'

        # Zatim zaključavamo zahtjev za brisanje.
        deletion_request = (
            AccountDeletionRequest.objects.select_for_update().filter(
                user_id=account.pk,
            ).first()
        )

        if deletion_request is None:
            return False, 'Request a confirmation code before deleting your account.'

        # Koristimo provjeru koju smo prethodno napravili.
        error = _validate_account_deletion_code(
            account,
            deletion_request,
            code,
        )

        if error:
            # Normalan izlazak sprema broj pogrešnih pokušaja.
            # Ovdje ne podižemo izuzetak koji bi poništio taj brojač.
            return False, error

        # Zaključavamo profil i čuvamo podatke njegove slike.
        profile = Profile.objects.select_for_update().filter(
            user_id=account.pk,
        ).first()

        image_name = None
        image_storage = None

        if profile is not None and profile.image:
            image_name = profile.image.name
            image_storage = profile.image.storage

        # Čuvamo obične vrijednosti prije brisanja User zapisa.
        account_id = account.pk
        recipient_email = account.email
        username = account.get_username()
        deleted_at = timezone.now()

        # Prekidamo postojeće prijave ovog korisnika.
        session_keys = []

        for session in Session.objects.filter(
            expire_date__gt=deleted_at,
        ).iterator():
            session_data = session.get_decoded()

            if session_data.get('_auth_user_id') == str(account_id):
                session_keys.append(session.session_key)

            if len(session_keys) >= 500:
                Session.objects.filter(session_key__in=session_keys).delete()
                session_keys.clear()

        if session_keys:
            Session.objects.filter(session_key__in=session_keys).delete()

        # CASCADE uklanja povezane zapise iz poslanih modela.
        account.delete()

        # Datoteka i email obrađuju se tek nakon uspješnog brisanja u bazi.
        def complete_account_deletion():
            if image_name and image_storage is not None:
                try:
                    # Ne brišemo datoteku ako je koristi još neki profil.
                    image_is_shared = Profile.objects.filter(
                        image=image_name,
                    ).exists()
                    
                    if not image_is_shared:
                        image_storage.delete(image_name)

                        # DODAO SAM OVO: nakon slike uklanjamo prazni folder korisnika.
                        _remove_empty_profile_directory(
                            image_storage,
                            account_id,
                        )

                except Exception:
                    logger.exception(
                        'Profile image cleanup failed for deleted user %s.',
                        account_id,
                    )

            try:
                sent = send_account_deleted_email(
                    recipient_email,
                    username,
                    deleted_at,
                )

                if sent != 1:
                    raise OSError('The mail backend did not confirm sending.')

            except (SMTPException, OSError):
                logger.exception(
                    'Sending the deletion notification failed for deleted user %s.',
                    account_id,
                )

        transaction.on_commit(complete_account_deletion)

    return True, 'Your account has been permanently deleted.'


# Uklanja korisnikov folder samo ako je prazan.
def _remove_empty_profile_directory(storage, user_id):
    directory_name = f'picture/profile_picture/{user_id}'

    try:
        directory_path = storage.path(directory_name)
    except NotImplementedError:
        # Cloud storage može imati samo virtualne foldere.
        return

    try:
        Path(directory_path).rmdir()
    except FileNotFoundError:
        # Folder je već uklonjen ili nije postojao.
        pass
    except OSError as error:
        # Folder s preostalim datotekama ne brišemo naslijepo.
        if error.errno not in (errno.ENOTEMPTY, errno.EEXIST):
            raise

