from django.conf import settings
from django.db import models
from django.utils import timezone

class AccountDeletionRequest(models.Model):
    # Jedan korisnik ima jedan zapis zahtjeva za brisanje.
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='deletion_request')

    # Adresa računa u trenutku izdavanja koda.
    email = models.EmailField(max_length=254, blank=True)

    # Čuvamo hash koda, a ne originalni kod iz emaila.
    code_hash = models.CharField(max_length=255, blank=True)

    # Potpis stanja računa; promjena emaila ili lozinke poništava kod.
    account_state = models.CharField(max_length=64, blank=True)

    # Vrijeme pripreme trenutnog koda.
    created_at = models.DateTimeField(default=timezone.now)

    # Rok važenja koda; prazno dok kod nije izdan.
    expires_at = models.DateTimeField(null=True, blank=True)

    # Broj pogrešnih pokušaja unosa trenutnog koda.
    failed_attempts = models.PositiveSmallIntegerField(default=0)

    # Početak perioda u kojem brojimo pokušaje slanja.
    send_window_started_at = models.DateTimeField(default=timezone.now)

    # Broj pokušaja slanja u tom periodu.
    send_count = models.PositiveSmallIntegerField(default=0)

    # Vrijeme posljednjeg pokušaja slanja, za razmak između zahtjeva.
    last_send_attempt_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f'Account deletion request for user {self.user_id}'

