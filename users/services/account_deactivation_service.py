from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.db import transaction
from django.utils import timezone
from ..models.profile_model import Profile

def deactivate_account(user):
    with transaction.atomic():
        # Prvo zaključavamo korisnika.
        account = get_user_model().objects.select_for_update().get(
            pk=user.pk,
        )

        # Zatim zaključavamo njegov profil.
        profile = Profile.objects.select_for_update().get(
            user_id=account.pk,
        )

        now = timezone.now()

        if profile.deactivated_at is None:
            profile.deactivated_at = now

        # iskorišteni potvrdni link više ne vrijedi.
        profile.deactivation_token_hash = None

        profile.save(update_fields=[
            'deactivated_at',
            'deactivation_token_hash',
        ])

        # Sprečavamo nove prijave.
        account.is_active = False
        account.save(update_fields=['is_active'])

        # Prekidamo postojeće prijave ovog korisnika.
        session_keys = []

        for session in Session.objects.filter(expire_date__gt=now).iterator():
            session_data = session.get_decoded()

            if session_data.get('_auth_user_id') == str(account.pk):
                session_keys.append(session.session_key)

            if len(session_keys) >= 500:
                Session.objects.filter(session_key__in=session_keys).delete()
                session_keys.clear()

        if session_keys:
            Session.objects.filter(session_key__in=session_keys).delete()

