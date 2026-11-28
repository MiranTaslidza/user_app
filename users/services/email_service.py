from django.core.mail import send_mail, EmailMultiAlternatives
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.utils import timezone
from django.urls import reverse
from django.contrib import messages
from django.template.loader import render_to_string
from .account_reactivation_token_service import TOKEN_MAX_AGE as REACTIVATION_TOKEN_MAX_AGE



# funkcija za slanje emaila
def send_verification_email(request, user): 
    uid = urlsafe_base64_encode(force_bytes(user.pk)) # kodiranje ID korisnika u base64 format kako bi se mogao sigurno koristiti u URL-u.
    token = default_token_generator.make_token(user) # generisanje tokena za verifikaciju korisnika. Token se koristi za potvrdu identiteta korisnika prilikom verifikacije email adrese.

    # kreiranje URL-a za verifikaciju email adrese. Koristi se funkcija reverse za generisanje URL-a na osnovu imena rute "verify_email" i prosleđuje se uid i token kao parametri.
    verification_path = reverse(
        "verify_email",
        kwargs={
            "uidb64": uid,
            "token": token,
        },
    )

    # kreiranje punog URL-a za verifikaciju email adrese. Funkcija build_absolute_uri generiše apsolutni URL na osnovu relativnog puta verification_path. Ovaj URL će biti poslat korisniku u emailu kako bi mogao potvrditi svoju email adresu.
    verification_url = request.build_absolute_uri(verification_path)

    # kreiranje poruke za email verifikaciju. Poruka sadrži pozdrav korisniku, uputstvo da klikne na link za verifikaciju i sam link (verification_url). Takođe, uključuje napomenu da ako korisnik nije napravio račun, može zanemariti poruku.
    subject = "Potvrda email adrese"

    # kreiranje poruke za email verifikaciju. Poruka sadrži pozdrav korisniku, uputstvo da klikne na link za verifikaciju i sam link (verification_url). Takođe, uključuje napomenu da ako korisnik nije napravio račun, može zanemariti poruku.
    message = (
        f"Pozdrav {user.username},\n\n"
        "Kliknite na sljedeći link kako biste potvrdili email adresu:\n\n"
        f"{verification_url}\n\n"
        "Ako niste napravili ovaj račun, zanemarite poruku."
    )

    # slanje emaila korisniku sa linkom za verifikaciju. Funkcija send_mail šalje email sa zadatim subjectom, porukom, adresom pošiljaoca (DEFAULT_FROM_EMAIL iz settings.py) i listom primalaca (u ovom slučaju samo korisnikova email adresa). Ako dođe do greške prilikom slanja emaila, postavlja se fail_silently na False kako bi se greška prijavila.
    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    
    messages.success(
        request,
        "A verification email has been sent. Please check your inbox and follow the link to verify your email address before signing in."
    )



# slanje poruke na promjenu lozinke
def send_password_changed_email(request, user):
    reset_url = request.build_absolute_uri(
        reverse("password_reset")
    )

    subject = "Your password has been changed"

    message = f"""
        Hello {user.username},

        This email confirms that your account password has been changed.

        If this was you, no further action is required.

        If you do not recognize this activity, you should reset your password immediately using the link below:

        {reset_url}

        If you need additional assistance, please contact support.

        Best regards,
        Security Team
    """

    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

# slanje poruke na stari email
def send_old_email_change_confirmation(request, email_change, token):
    """Šalje link za potvrdu promjene na stari email."""

    verification_url = request.build_absolute_uri(
        reverse("email_change_old_verify", kwargs={"token": token})
    )

    context = {
        "user": email_change.user,
        "email_change": email_change,
        "verification_url": verification_url,
    }

    html_message = render_to_string("users/email_change_old_confirmation.html", context)

    text_message = (
        f"Hello {email_change.user.username},\n\n"
        "A request was made to change your email address.\n\n"
        "If you requested this change, confirm it using this link:\n\n"
        f"{verification_url}\n\n"
        "If you did not request this change, ignore this message."
    )

    email = EmailMultiAlternatives(
        subject="Confirm email change request",
        body=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[email_change.old_email],
    )

    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)


# slanje emaila na novi email
def send_new_email_change_confirmation(request, email_change, token):
    """Šalje potvrdu na novu email adresu nakon potvrde starog emaila."""

    verification_url = request.build_absolute_uri(
        reverse("email_change_new_verify", kwargs={"token": token})
    )

    context = {
        "user": email_change.user,
        "email_change": email_change,
        "verification_url": verification_url,
    }

    html_message = render_to_string("users/email_change_new_confirmation.html", context)

    text_message = (
        f"Hello {email_change.user.username},\n\n"
        "Confirm your new email address using this link:\n\n"
        f"{verification_url}\n\n"
        "If you did not request this change, ignore this email."
    )

    email = EmailMultiAlternatives(
        subject="Confirm your new email address",
        body=text_message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=[email_change.new_email],
    )

    email.attach_alternative(html_message, "text/html")
    email.send(fail_silently=False)



# obavještava prethodnu adresu o završenoj promjeni.
def send_email_change_completed_notification(email_change):
    subject = "Your account email address has been changed"

    message = (
        f"Hello {email_change.user.username},\n\n"
        "The email address associated with your account has been changed.\n\n"
        f"Previous email address: {email_change.previous_email}\n\n"
        "A new password was also set as part of this change.\n"
        "Existing signed-in sessions have been invalidated.\n\n"
        "If you made this change, no further action is required.\n\n"
        "If you did not authorize this change, contact support immediately.\n\n"
        "Security Team"
    )

    send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email_change.previous_email],
        fail_silently=False,
    )



# Šalje link za potvrdu deaktivacije na trenutni email korisnika.
def send_account_deactivation_confirmation(user, token):
    # Link pravimo pomoću osnovne adrese aplikacije iz postavki.
    confirmation_path = reverse(
        'account_deactivation_confirm',
        kwargs={'token': token},
    )

    confirmation_url = settings.APP_BASE_URL.rstrip('/') + confirmation_path

    subject = 'Confirm your account deactivation'

    message = (
        f'Hello {user.username},\n\n'
        'We received a request to deactivate your account.\n\n'
        'To continue, open the link below and confirm your decision:\n\n'
        f'{confirmation_url}\n\n'
        'This link expires 15 minutes after the request was created.\n\n'
        'Deactivating your account will prevent sign-in and '
        'sign you out on all devices. Your account data will be retained.\n\n'
        'If you did not request this, do not confirm the deactivation. '
        'Your account will remain active.\n\n'
        'Do not share this link with anyone.\n\n'
        'Security Team'
    )

    return send_mail(
        subject=subject,
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    ) 


# Obavještava korisnika da je deaktivacija završena.
def send_account_deactivation_completed_notification(user, deactivated_at):
    deactivated_at_text = timezone.localtime(deactivated_at).strftime(
        '%d.%m.%Y. %H:%M:%S %Z'
    )

    message = (
        f'Hello {user.username},\n\n'
        'Your account has been deactivated.\n\n'
        f'Deactivation time: {deactivated_at_text}\n\n'
        'You have been signed out on all devices, '
        'and sign-in is currently disabled.\n\n'
        'Your account data has been retained.\n\n'
        'If you did not authorize this action, please contact support.\n\n'
        'Security Team'
    )

    return send_mail(
        subject='Your account has been deactivated',
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )

def send_account_reactivation_email(user, token):
    # Link povezuje korisnika s njegovim potpisanim tokenom.
    reactivation_path = reverse(
        'account_reactivation_confirm',
        kwargs={
            'user_id': user.pk,
            'token': token,
        },
    )

    reactivation_url = settings.APP_BASE_URL.rstrip('/') + reactivation_path

    # Rok u poruci preuzimamo iz istog pravila koje provjerava token.
    expires_in_minutes = REACTIVATION_TOKEN_MAX_AGE // 60

    message = (
        f'Hello {user.username},\n\n'
        'We received a request to reactivate your account.\n\n'
        'To reactivate your account, click the link below:\n\n'
        f'{reactivation_url}\n\n'
        f'This link expires {expires_in_minutes} minutes '
        'after it was created.\n\n'
        'After reactivation, you can sign in using your usual sign-in method.\n\n'
        'If you did not request this, ignore this email. '
        'Your account will remain deactivated.\n\n'
        'Do not share this link with anyone.\n\n'
        'Security Team'
    )

    return send_mail(
        subject='Reactivate your account',
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    

# Šalje link za ponovno aktiviranje deaktiviranog računa.
def send_account_reactivation_email(user, token):
    # Link povezuje korisnika s njegovim potpisanim tokenom.
    reactivation_path = reverse(
        'account_reactivation_confirm',
        kwargs={
            'user_id': user.pk,
            'token': token,
        },
    )

    reactivation_url = settings.APP_BASE_URL.rstrip('/') + reactivation_path

    # Rok u poruci preuzimamo iz istog pravila koje provjerava token.
    expires_in_minutes = REACTIVATION_TOKEN_MAX_AGE // 60

    message = (
        f'Hello {user.username},\n\n'
        'We received a request to reactivate your account.\n\n'
        'To reactivate your account, click the link below:\n\n'
        f'{reactivation_url}\n\n'
        f'This link expires {expires_in_minutes} minutes '
        'after it was created.\n\n'
        'After reactivation, you can sign in using your usual sign-in method.\n\n'
        'If you did not request this, ignore this email. '
        'Your account will remain deactivated.\n\n'
        'Do not share this link with anyone.\n\n'
        'Security Team'
    )

    return send_mail(
        subject='Reactivate your account',
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )
    

# Šalje potvrdni kod za trajno brisanje računa.
def send_account_deletion_code_email(user, code, expires_at):
    # Prikazujemo stvarni rok važenja spremljenog koda.
    expires_at_text = timezone.localtime(expires_at).strftime(
        '%d.%m.%Y. %H:%M:%S %Z'
    )

    message = (
        f'Hello {user.username},\n\n'
        'We received a request to permanently delete your account.\n\n'
        'Your confirmation code is:\n\n'
        f'{code}\n\n'
        f'This code expires on: {expires_at_text}.\n\n'
        'Return to the account deletion page, enter this code, '
        'and select Permanently delete account to complete the deletion.\n\n'
        'Requesting this code has not deleted your account.\n\n'
        'If you did not request account deletion, ignore this email '
        'and do not share this code with anyone.\n\n'
        'Security Team'
    )

    return send_mail(
        subject='Confirm your account deletion',
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
    )



# Šalje obavijest nakon uspješnog brisanja računa.
# Podatke primamo kao obične vrijednosti jer User više ne postoji.
def send_account_deleted_email(email, username, deleted_at):
    deleted_at_text = timezone.localtime(deleted_at).strftime(
        '%d.%m.%Y. %H:%M:%S %Z'
    )

    message = (
        f'Hello {username},\n\n'
        'Your account has been permanently deleted.\n\n'
        f'Deletion time: {deleted_at_text}\n\n'
        'Your existing sign-in sessions have been terminated.\n\n'
        'If you did not authorize this action, please contact support.\n\n'
        'Security Team'
    )

    return send_mail(
        subject='Your account has been deleted',
        message=message,
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[email],
        fail_silently=False,
    )    
    


