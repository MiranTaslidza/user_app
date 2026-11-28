from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

class EmailChange(models.Model):
    # Korisnik kojem zahtjev pripada. on_delete=models.CASCADE znači da se brisanjem korisnika briše i ovaj zapis.
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    # Email koji korisnik ima kada pokrene trenutni zahtjev. Na njega šalješ prvu potvrdu.
    old_email = models.EmailField(max_length=254)
    # Nova adresa koju korisnik želi postaviti. Ona još nije upisana u User.email.
    new_email = models.EmailField(max_length=254)
    # Email koji je korišten prije posljednje uspješne promjene. Čuvaš ga za eventualni oporavak. Novi nepotvrđeni zahtjev ga ne mijenja.
    previous_email = models.EmailField(max_length=254, blank=True)
    # Vrijeme posljednje uspješne promjene emaila. Ostaje sačuvano dok se ne završi sljedeća promjena.
    email_changed_at = models.DateTimeField(null=True, blank=True)

    # potvrda starog emaila
    # Hash tokena iz linka poslanog na stari email. Originalni token ide u email; njegov hash čuvaš u bazi i koristiš za provjeru.
    old_email_token_hash = models.CharField(max_length=64, unique=True)
    # Govori je li korisnik potvrdio zahtjev putem starog emaila. Počinje kao False.
    old_email_verified = models.BooleanField(default=False)
    # Vrijeme kada je potvrđen zahtjev putem starog emaila. Do tada je prazno.
    old_email_verified_at = models.DateTimeField(null=True, blank=True)

    # potvrda novog emaila
    # Hash drugog tokena, poslanog na novi email. Može biti prazan dok se ne završi potvrda starog emaila.
    new_email_token_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)
    # Govori je li potvrđena nova email adresa. Počinje kao False.
    new_email_verified = models.BooleanField(default=False)
    # Vrijeme potvrde nove email adrese. Do tada je prazno.
    new_email_verified_at = models.DateTimeField(null=True, blank=True)
    # Vrijeme pokretanja trenutnog zahtjeva. default=timezone.now ga automatski postavlja pri kreiranju zapisa. Pri ponovnom korištenju zapisa moraš ga izričito osvježiti.
    created_at = models.DateTimeField(default=timezone.now)
    # Rok do kojeg zahtjev vrijedi. Nakon tog vremena potvrde se odbijaju.
    expires_at = models.DateTimeField()
    # Vrijeme kada je zahtjev uspješno iskorišten i nova adresa spremljena u User.email.
    used_at = models.DateTimeField(null=True, blank=True)
    # Vrijeme kada je zahtjev otkazan. Ako nije otkazan, ostaje prazno.
    cancelled_at = models.DateTimeField(null=True, blank=True)
    # Govori je li zahtjev još otvoren. Nakon uspješne promjene ili otkazivanja postavljaš ga na False. Ne odnosi se na aktivnost korisničkog računa.
    is_active = models.BooleanField(default=True)
    # IP zahtjeva kojim je potvrđen link na starom emailu.
    old_email_verified_ip = models.GenericIPAddressField(null=True, blank=True)
    # IP zahtjeva kojim je potvrđen link na novom emailu.
    new_email_verified_ip = models.GenericIPAddressField(null=True, blank=True)

    def __str__(self):
        return (
            f"{self.user.username} "
            f"email change "
            f"{self.old_email} → {self.new_email}"
        )

