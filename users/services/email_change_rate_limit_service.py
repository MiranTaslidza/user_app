from datetime import timedelta
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from ..models.email_change_rate_limit_model import EmailChangeRateLimit

# DODAO SAM OVU FUNKCIJU: provjerava ograničenje i bilježi dozvoljeni pokušaj.
def check_email_change_rate_limit(user):
    with transaction.atomic():
        # Zaključavamo korisnika da istovremeni zahtjevi
        # ne mogu istovremeno kreirati ili mijenjati njegove brojače.
        locked_user = get_user_model().objects.select_for_update().get(pk=user.pk)

        rate_limit, _ = EmailChangeRateLimit.objects.get_or_create(user=locked_user)

        now = timezone.now()

        # Ako je prošao jedan sat, započinjemo novi period brojanja.
        if now >= rate_limit.window_started_at + timedelta(hours=1):
            rate_limit.window_started_at = now
            rate_limit.attempt_count = 0

        # Između dozvoljenih pokušaja mora proći najmanje 60 sekundi.
        if rate_limit.last_attempt_at:
            next_allowed_at = rate_limit.last_attempt_at + timedelta(seconds=60)

            if now < next_allowed_at:
                return "Please wait 60 seconds between attempts."

        # U jednom periodu dozvoljavamo najviše 5 pokušaja.
        if rate_limit.attempt_count >= 5:
            return "You have reached the limit of 5 attempts per hour. Please try again later."

        # Pokušaj je dozvoljen: povećavamo brojač i bilježimo vrijeme.
        rate_limit.attempt_count += 1
        rate_limit.last_attempt_at = now

        rate_limit.save(update_fields=[
            "window_started_at",
            "attempt_count",
            "last_attempt_at",
        ])

    return None

