from django.conf import settings
from django.db import models

class Address(models.Model):
    # Korisnik kojem adresa pripada.
    # Brisanjem računa brišu se i njegove adrese.
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='addresses')

    # Neobavezni naziv radi lakšeg prepoznavanja, npr. Home ili Work.
    label = models.CharField(max_length=50, blank=True)

    # Osnovni podaci adrese.
    country = models.CharField(max_length=100)
    city = models.CharField(max_length=100)
    postal_code = models.CharField(max_length=20)
    street = models.CharField(max_length=200)
    house_number = models.CharField(max_length=30)

    # Neobavezni dodatak: stan, sprat, ulaz ili drugi podatak.
    address_line_2 = models.CharField(max_length=200, blank=True)

    # Označava zadanu adresu korisnika.
    is_default = models.BooleanField(default=False)

    class Meta:
        # Zadana adresa prikazuje se prva.
        ordering = ['-is_default', '-pk']

    def __str__(self):
        return f'{self.street} {self.house_number}, {self.postal_code} {self.city}, {self.country}'
