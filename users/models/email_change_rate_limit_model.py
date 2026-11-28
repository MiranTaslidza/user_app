from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class EmailChangeRateLimit(models.Model):
    # Jedan zapis s brojačima po korisniku.
    user = models.OneToOneField(User, on_delete=models.CASCADE)

    # Početak jednosatnog perioda za brojanje pokušaja.
    window_started_at = models.DateTimeField(default=timezone.now)

    # Broj pokušaja u tom periodu.
    attempt_count = models.PositiveIntegerField(default=0)

    # Vrijeme posljednjeg dozvoljenog pokušaja.
    last_attempt_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.user.username

