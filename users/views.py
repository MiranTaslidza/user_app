#models
from django.shortcuts import render, get_object_or_404, redirect
from django.views.generic import UpdateView, DetailView, FormView
from django.views.generic.edit import CreateView 
from django.urls import reverse_lazy, reverse
from django.http import HttpResponse # za prikaz poruke nakon slanja emaila
from django.contrib.auth.tokens import default_token_generator # za generisanje tokena za verifikaciju email adrese
from django.shortcuts import redirect
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages
from django.core.cache import cache
from django.views.decorators.http import require_POST
from django.views import View
import logging
import secrets
import requests
from google.auth.exceptions import GoogleAuthError
from django.core.validators import validate_email
from django.db import IntegrityError, transaction
from django.core.exceptions import ValidationError
from django.contrib.auth import login, logout, update_session_auth_hash, get_user_model
from uuid import uuid4
from users.models.profile_model import Profile
logger = logging.getLogger(__name__)
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordResetConfirmView, PasswordChangeView, PasswordChangeDoneView
from django.contrib.messages.views import SuccessMessageMixin
from smtplib import SMTPException
from datetime import timedelta
import hashlib
from django.utils import timezone
from django.contrib.sessions.models import Session 


# services
from .services.email_service import send_verification_email, send_password_changed_email, send_old_email_change_confirmation, send_new_email_change_confirmation, send_email_change_completed_notification
from .services.google_oauth_service import get_google_authorization_url, exchange_code_for_token, verify_google_id_token
from .services.email_change_rate_limit_service import check_email_change_rate_limit


#forms
from .forms.user_creation_form import RegisterForm
from .forms.profile_form import ProfileForm
from .forms.profile_update import ProfileUpdateForm
from .forms.email_change_form import EmailChangeForm
from django.contrib.auth.forms import SetPasswordForm

#models
from django.contrib.auth.models import User
from .models.email_change_model import EmailChange

# Create your views here.


class CustomPasswordResetView(SuccessMessageMixin, PasswordResetView):
    success_url = reverse_lazy('login')
    success_message = (
        'If an eligible account matches this email address, you will receive a password reset link. '
        'Please check your inbox and spam folder.'
    )


class CustomPasswordResetConfirmView(SuccessMessageMixin, PasswordResetConfirmView):
    success_url = reverse_lazy('login')
    success_message = 'Your password has been reset successfully. You can now sign in with your new password.'


############# user CBV #######################
def home(request):
    return render(request, 'users/home.html')

#register
class RegisterView(CreateView):
    form_class = RegisterForm
    template_name = 'users/register.html'
    success_url = reverse_lazy('login')
    
    #funkcija za slanje emaila nakon registracije
    def form_valid(self, form):
        # Korisnik će biti spremljen kao neaktivan
        form.instance.is_active = False
        
        # Prvo sačuvaj korisnika
        response = super().form_valid(form)

        # Pošalji verifikacijski email
        send_verification_email(self.request, self.object)

        # Nastavi normalan tok
        return response


# promjena passworda
class CustomPasswordChangeView(PasswordChangeView):
    template_name = "users/password_change_form.html"
    # success_url = reverse_lazy("password_change_done")
    success_url = reverse_lazy("home") # obavezno preusmjerenje promjenit
    
    # da bi me poruka prikazivala mmora iči u funkciju
    def form_valid(self, form):
        # Django sprema novu lozinku i održava korisnika prijavljenim.
        response = super().form_valid(form)

        messages.success(
            self.request,
            'Lozinka je uspješno promijenjena.',
        )

        # Pokušaj poslati email obavijest.
        try:
            send_password_changed_email(
                request=self.request,
                user=self.request.user,
            )

        # Ako slanje ne uspije, zapiši grešku i obavijesti korisnika.
        except (SMTPException, OSError):
            logger.exception(
                'Slanje obavijesti o promjeni lozinke nije uspjelo.'
            )

            messages.warning(
                self.request,
                'Lozinka je promijenjena, ali email obavijest '
                'nije mogla biti poslana.',
            )

        return response




######## verifikacija maila #############

# funkcija za verifikaciju emaila
def verify_email(request, uidb64, token):
    try:
        # Dekodira ID korisnika iz URL-a
        uid = urlsafe_base64_decode(uidb64).decode()

        # Pronalazi korisnika u bazi
        user = User.objects.get(pk=uid)

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    
    # Provjerava da li je korisnik već aktivan   
    if user is not None and user.is_active:
        messages.info(request, "Your email has already been verified.")
        return redirect('login')

    # Provjerava da li korisnik postoji i da li je token ispravan
    if user is not None and default_token_generator.check_token(user, token):

        user.is_active = True
        user.save()
        
        messages.success(
            request,
            "Your email has been successfully verified. You can now log in."
        )

        #return HttpResponse("Email has been successfully verified.")
        return redirect('login')
    
    # Korisnik postoji, ali token nije ispravan ili je istekao
    if user is not None and not user.is_active:
        request.session['verification_user_id'] = user.pk

        messages.warning(
            request,
            'The verification link is broken or has expired. '
            'Request a new link.',
        )

        return redirect('verification_email_sent')

    return HttpResponse("The verification link is invalid or the account has already been activated.")





# verifikacijski email template
def verification_email_sent(request):
    return render(
        request,
        "users/verification_email_sent.html"
    )


# ponovno slanje verifikacijskog linka
@require_POST
def resend_verification_email(request):
    user_id = request.session.get('verification_user_id')
    user = User.objects.filter(pk=user_id, is_active=False).first()

    if user is None:
        return redirect('login')

    # Ograniči ponovno slanje na jednom u 60 sekundi
    cache_key = f'verification_resend_{user.pk}'

    if not cache.add(cache_key, True, timeout=60):
        messages.info(request, 'Sačekajte 60 sekundi prije ponovnog slanja.')
        return redirect('verification_email_sent')

    try:
        send_verification_email(request, user)
    except Exception:
        cache.delete(cache_key)
        raise

    messages.success(request, 'Novi verifikacijski email je poslan.')
    return redirect('login')

##################### proflie ##########################
# kreiranje profila nakon registracije
class ProfileDetailView(DetailView):
    model = Profile
    template_name = 'users/profile_detail.html'
    context_object_name = 'profile'

    def get_queryset(self):
        return Profile.objects.select_related('user')


class ProfileCreateView(LoginRequiredMixin, UpdateView):
    form_class = ProfileForm
    template_name = 'users/profile_create.html'
    success_url = reverse_lazy('home')

    # pronalazi profil prijavljenog korisnika.
    # Ako profil ne postoji, odmah kreira prazan zapis u bazi.
    # UpdateView taj zapis prosljeđuje formi kao instance.
    def get_object(self, queryset=None):
        profile, _ = Profile.objects.get_or_create(
            user=self.request.user,
        )
        return profile


# preusmjerenje na profile nakon registracije
class CustomLoginView(LoginView):
    def get_success_url(self):
        # Nakon uspješne prijave provjerava postoji li profil.
        if not Profile.objects.filter(user=self.request.user).exists():
            return reverse('profile')

        return super().get_success_url()


# update username, name, f_name, l_name, bio, phone, img
class ProfileUpdateView(LoginRequiredMixin, UpdateView):
    form_class = ProfileUpdateForm
    template_name = 'users/profile_update.html'
    
    # uzima profil prijavljenog korisnika. UpdateView ga automatski prosljeđuje formi kao instance.
    def get_object(self, queryset=None):
        return self.request.user.profile

    # nakon spremanja vodi na prikaz profila.
    def get_success_url(self):
        return reverse(
            'profile_detail',
            kwargs={'pk': self.object.pk})



##############google login reg########################

# google login
class GoogleLoginView(View):
    """
    Pokreće Google OAuth prijavu.

    Kada korisnik otvori ovaj view,
    Django ga preusmjerava na Google login stranicu.
    """

    def get(self, request):
        if request.user.is_authenticated:
            if not request.user.has_usable_password():
                return redirect('set_initial_password')
            return redirect('home')

        google_url = get_google_authorization_url(request)
        return redirect(google_url)

class GoogleCallbackView(View):
    def login_error(self, request, log_message, user_message):
        logger.warning(log_message)
        messages.error(request, user_message)
        return redirect('login')

    def get(self, request):
        # Već prijavljen korisnik ne treba novu prijavu.
        if request.user.is_authenticated:
            if not request.user.has_usable_password():
                return redirect('set_initial_password')
            return redirect('home')

        # Uzimamo i uklanjamo podatke započete Google prijave.
        expected_state = request.session.pop('google_oauth_state', None)
        expected_nonce = request.session.pop('google_oauth_nonce', None)

        received_state = request.GET.get('state')

        # Google odgovor mora pripadati ovom browseru i zahtjevu.
        if (
            not expected_state
            or not received_state
            or not expected_nonce
            or not secrets.compare_digest(expected_state, received_state)
        ):
            messages.error(
                request,
                'Google prijava nije važeća. Pokušajte ponovo.',
            )
            return redirect('login')

        # Korisnik je odustao ili je Google vratio grešku.
        if request.GET.get('error'):
            messages.error(request, 'Google prijava nije završena.')
            return redirect('login')

        code = request.GET.get('code')

        if not code:
            messages.error(request, 'Google nije vratio kod za prijavu.')
            return redirect('login')

        try:
            # Postojeći servis razmjenjuje code za tokene.
            token_data = exchange_code_for_token(code)

            if not isinstance(token_data, dict):
                raise ValueError('Invalid token response.')

            raw_id_token = token_data.get('id_token')

            if not isinstance(raw_id_token, str) or not raw_id_token:
                raise ValueError('Missing ID token.')

            # Nova funkcija provjerava potpis, istek, Client ID i nonce.
            google_user = verify_google_id_token(
                raw_id_token,
                expected_nonce,
            )

        except (requests.RequestException, GoogleAuthError, ValueError):
            return self.login_error(
                request,
                'Google token verification failed.',
                'Google prijava nije uspjela. Pokušajte ponovo.',
            )

        google_id = google_user.get('sub')
        email = google_user.get('email')

        # Prihvatamo samo provjeren identitet s potvrđenim emailom.
        if (
            not isinstance(google_id, str)
            or not google_id
            or not isinstance(email, str)
            or google_user.get('email_verified') is not True
        ):
            messages.error(
                request,
                'Google nije potvrdio potrebne podatke korisnika.',
            )
            return redirect('login')

        email = email.strip()

        try:
            validate_email(email)
        except ValidationError:
            messages.error(request, 'Email adresa nije ispravna.')
            return redirect('login')

        if len(email) > 254:
            messages.error(request, 'Email adresa je preduga.')
            return redirect('login')

        # Ovaj postupak prepoznaje korisnika prema emailu.
        # Dopuštamo adrese nad kojima Google potvrđuje vlasništvo.
        google_controls_email = (
            email.lower().endswith('@gmail.com')
            or bool(google_user.get('hd'))
        )

        if not google_controls_email:
            messages.error(
                request,
                'Za ovu adresu koristite prijavu emailom i lozinkom. '
                'Google prijava podržava Gmail i Google Workspace adrese.',
            )
            return redirect('login')

        # Email u tvojoj bazi već ima UNIQUE ograničenje.
        user = User.objects.filter(email__iexact=email).first()

        if user is None:
            first_name = google_user.get('given_name', '')
            last_name = google_user.get('family_name', '')

            if not isinstance(first_name, str):
                first_name = ''

            if not isinstance(last_name, str):
                last_name = ''

            try:
                with transaction.atomic():
                    user = User(
                        username=f'g_{uuid4().hex}',
                        email=email,
                        first_name=first_name[:150],
                        last_name=last_name[:150],
                        is_active=True,
                    )

                    # Ne izmišljamo lozinku za Google korisnika.
                    user.set_unusable_password()
                    user.save()

            except IntegrityError:
                # Drugi zahtjev je možda upravo kreirao isti račun.
                user = User.objects.filter(email__iexact=email).first()

                if user is None:
                    return self.login_error(
                        request,
                        'Google user creation failed.',
                        'Kreiranje računa nije uspjelo. Pokušajte ponovo.',
                    )

        # Postojeći neaktivan račun ostaje neaktivan.
        if not user.is_active:
            request.session['verification_user_id'] = user.pk

            messages.warning(
                request,
                'Račun nije aktivan. Potvrdite email '
                'putem verifikacijskog linka.',
            )
            return redirect('verification_email_sent')

        # Django upisuje korisnika u prijavljenu sesiju.
        login(
            request,
            user,
            backend='users.backend.UsernameOrEmailBackend',
        )

        if not user.has_usable_password():
            return redirect('set_initial_password')

        if not Profile.objects.filter(user=user).exists():
            return redirect('profile')

        messages.success(request, 'Uspješno ste prijavljeni preko Googlea.')
        return redirect('home')


# prijavljen korisnik postavlja prvu lokalnu lozinku poslije krieranja profila.
class SetInitialPasswordView(LoginRequiredMixin, FormView):
    template_name = 'users/set_initial_password.html'
    form_class = SetPasswordForm

    def dispatch(self, request, *args, **kwargs):
        # korisniku koji već ima lozinku
        # ova stranica nije potrebna.
        if request.user.is_authenticated and request.user.has_usable_password():
            if not Profile.objects.filter(user_id=request.user.pk).exists():
                return redirect('profile')

            return redirect('home')

        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()

        # forma postavlja lozinku prijavljenom korisniku.
        # Ne traži staru lozinku jer ona još ne postoji.
        kwargs['user'] = self.request.user
        return kwargs

    def form_valid(self, form):
        with transaction.atomic():
            # ponovo provjeravamo stanje pod zaključavanjem.
            # Dva otvorena taba ne mogu prepisati već postavljenu lozinku.
            user = User.objects.select_for_update().get(
                pk=self.request.user.pk,
            )

            if not user.is_active:
                logout(self.request)
                messages.error(
                    self.request,
                    'This account is not available for sign-in.',
                )
                return redirect('login')

            if user.has_usable_password():
                messages.info(
                    self.request,
                    'Your account already has a password.',
                )
                return redirect('home')

            # spremamo lozinku na svježe učitanom korisniku.
            user.set_password(form.cleaned_data['new_password1'])
            user.save(update_fields=['password'])

        # korisnik ostaje prijavljen nakon spremanja.
        # Django po potrebi osvježava i zapis lozinke u trenutnoj sesiji.
        update_session_auth_hash(self.request, user)

        messages.success(
            self.request,
            'Your password has been set. '
            'You can now sign in with Google or your email and password.',
        )

        # nakon lozinke slijedi kreiranje profila.
        if not Profile.objects.filter(user_id=user.pk).exists():
            return redirect('profile')

        return redirect('home')

########## change  email #############

class EmailChangeView(LoginRequiredMixin, FormView):
    form_class = EmailChangeForm
    template_name = "users/email_change.html"
    success_url = reverse_lazy("home")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['pending_email_change'] = EmailChange.objects.filter(
            user=self.request.user,
            is_active=True,
            cancelled_at__isnull=True,
            used_at__isnull=True,
            new_email_verified=False,
            expires_at__gt=timezone.now(),
        ).first()
        return context

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["user"] = self.request.user
        return kwargs

    def form_valid(self, form):
        # provjerava 60 sekundi razmaka i 5 pokušaja na sat.
        rate_limit_error = check_email_change_rate_limit(self.request.user)

        # kod prekoračenja prikazuje grešku bez pravljenja tokena.
        if rate_limit_error:
            form.add_error(None, rate_limit_error)
            return self.form_invalid(form)

        now = timezone.now()
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with transaction.atomic():
            # Zaključavamo korisnikov zapis dok pripremamo zahtjev.
            user = get_user_model().objects.select_for_update().get(pk=self.request.user.pk)

            email_change = EmailChange.objects.filter(user=user).first()

            # Ne prepisujemo zahtjev koji još vrijedi.
            if email_change and email_change.is_active and email_change.expires_at > now:
                form.add_error(None, "An email change request is already pending.")
                return self.form_invalid(form)

            email_change, _ = EmailChange.objects.update_or_create(
                user=user,
                defaults={
                    "old_email": user.email,
                    "new_email": form.cleaned_data["new_email"],
                    "old_email_token_hash": token_hash,
                    "old_email_verified": False,
                    "old_email_verified_at": None,
                    "old_email_verified_ip": None,
                    "new_email_token_hash": None,
                    "new_email_verified": False,
                    "new_email_verified_at": None,
                    "new_email_verified_ip": None,
                    "created_at": now,
                    "expires_at": now + timedelta(hours=24),
                    "used_at": None,
                    "cancelled_at": None,
                    "is_active": True,
                },
            )

        send_old_email_change_confirmation(self.request, email_change, token)

        messages.success(
            self.request,
            "Confirmation link has been sent to your current email address."
        )

        return super().form_valid(form)





# uzima potvrdu sa starog emaila i šalje potvrdu na novi email
class EmailChangeOldVerifyView(View):
    template_name = "users/email_change_old_verify.html"

    def get(self, request, token):
        # Otvaranje linka samo prikazuje dugme za potvrdu.
        return render(request, self.template_name)

    def post(self, request, token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        new_token = secrets.token_urlsafe(32)
        new_token_hash = hashlib.sha256(new_token.encode()).hexdigest()

        with transaction.atomic():
            email_change = get_object_or_404(
                EmailChange.objects.select_for_update(),
                old_email_token_hash=token_hash,
            )

            if not email_change.is_active:
                messages.error(request, "This email change request is no longer active.")
                return redirect("home")

            if email_change.expires_at <= timezone.now():
                email_change.is_active = False
                email_change.save(update_fields=["is_active"])

                messages.error(request, "This email change request has expired.")
                return redirect("home")

            if email_change.old_email_verified:
                messages.info(request, "Your old email has already been confirmed.")
                return redirect("home")

            # Zahtjev mora još pripadati trenutnoj email adresi korisnika.
            user = get_user_model().objects.select_for_update().get(pk=email_change.user_id)

            if user.email.casefold() != email_change.old_email.casefold():
                email_change.is_active = False
                email_change.save(update_fields=["is_active"])

                messages.error(request, "This request no longer matches your current email address.")
                return redirect("home")

            email_change.old_email_verified = True
            email_change.old_email_verified_at = timezone.now()
            email_change.new_email_token_hash = new_token_hash

            email_change.save(update_fields=[
                "old_email_verified",
                "old_email_verified_at",
                "new_email_token_hash",
            ])

        try:
            send_new_email_change_confirmation(request, email_change, new_token)

        except (SMTPException, OSError):
            logger.exception("Sending the new email confirmation failed.")

            # Omogućava novi pokušaj potvrde ako slanje nije uspjelo.
            # Filter sprečava izmjenu eventualnog novijeg zahtjeva.
            EmailChange.objects.filter(
                pk=email_change.pk,
                old_email_token_hash=token_hash,
                new_email_token_hash=new_token_hash,
                is_active=True,
                new_email_verified=False,
            ).update(
                old_email_verified=False,
                old_email_verified_at=None,
                new_email_token_hash=None,
            )

            messages.error(request, "The confirmation email could not be sent. Please try again.")
            return render(request, self.template_name)

        messages.success(request, "Your old email has been confirmed. Check your new email address.")
        return redirect("home")



# Završna potvrda novog emaila, promjena adrese i odjava sesija
# Završna potvrda novog emaila, promjena adrese i odjava sesija
class EmailChangeNewVerifyView(View):

    # def get(self, request, token):
    #  postojeći postupak pokreće se slanjem forme.
    def post(self, request, token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        User = get_user_model()

        try:
            with transaction.atomic():
                email_change = get_object_or_404(
                    EmailChange.objects.select_for_update(),
                    new_email_token_hash=token_hash,
                )

                now = timezone.now()

                if not email_change.is_active or email_change.cancelled_at or email_change.used_at or email_change.new_email_verified:
                    messages.error(request, "This email change request is no longer active.")
                    return redirect("home")

                if email_change.expires_at <= now:
                    email_change.is_active = False
                    email_change.save(update_fields=["is_active"])

                    messages.error(request, "This email change request has expired.")
                    return redirect("home")

                if not email_change.old_email_verified:
                    messages.error(request, "Old email address has not been verified.")
                    return redirect("home")

                user = User.objects.select_for_update().get(pk=email_change.user_id)

                if user.email.casefold() != email_change.old_email.casefold():
                    email_change.is_active = False
                    email_change.save(update_fields=["is_active"])

                    messages.error(request, "This request no longer matches your current email address.")
                    return redirect("home")

                if User.objects.filter(email__iexact=email_change.new_email).exclude(pk=user.pk).exists():
                    email_change.is_active = False
                    email_change.save(update_fields=["is_active"])

                    messages.error(request, "The new email address is already in use.")
                    return redirect("home")

                #  neaktivan račun ne može završiti promjenu.
                if not user.is_active:
                    messages.error(request, "This account is inactive.")
                    return redirect("home")

                #  priprema i provjera unesene nove lozinke.
                # Privremeno koristimo novi email za provjere sličnosti lozinke.
                current_email = user.email
                user.email = email_change.new_email
                form = SetPasswordForm(user=user, data=request.POST)
                valid = form.is_valid()
                user.email = current_email

                #  nova lozinka ne smije biti ista kao stara.
                new_password = form.cleaned_data.get("new_password1")

                if new_password and user.check_password(new_password):
                    form.add_error("new_password1", "Your new password must be different from your current password.")
                    valid = False

                #  kod greške ponovo prikazuje formu.
                # Postojeći email i lozinka ostaju nepromijenjeni.
                if not valid:
                    return render(request, "users/email_change_new_verify.html", {"form": form})

                # Čuvamo podatke o prethodnom emailu.
                email_change.previous_email = user.email
                email_change.email_changed_at = now

                # Postavljamo novu adresu.
                user.email = email_change.new_email

                # user.save(update_fields=["email"])

                #  forma postavlja hash nove lozinke.
                user = form.save(commit=False)

                #  zajedno sprema novi email i novu lozinku.
                user.save(update_fields=["email", "password"])

                # Zatvaramo uspješno završen zahtjev.
                email_change.new_email_verified = True
                email_change.new_email_verified_at = now
                email_change.used_at = now
                email_change.is_active = False

                email_change.save(update_fields=[
                    "previous_email",
                    "email_changed_at",
                    "new_email_verified",
                    "new_email_verified_at",
                    "used_at",
                    "is_active",
                ])

                # Pronalazimo i brišemo postojeće sesije ovog korisnika.
                session_keys = []

                for session in Session.objects.filter(expire_date__gt=now).iterator():
                    session_data = session.get_decoded()

                    if session_data.get("_auth_user_id") == str(user.pk):
                        session_keys.append(session.session_key)

                    if len(session_keys) >= 500:
                        Session.objects.filter(session_key__in=session_keys).delete()
                        session_keys.clear()

                if session_keys:
                    Session.objects.filter(session_key__in=session_keys).delete()

        except IntegrityError:
            messages.error(request, "The email change could not be completed. Please try again.")
            return redirect("home")

        # Očistimo i trenutnu sesiju ako pripada istom korisniku.
        if request.user.is_authenticated and request.user.pk == user.pk:
            logout(request)

        # nakon uspješne promjene šalje obavijest
        # na prethodni email preko postojećeg servisa.
        try:
            send_email_change_completed_notification(email_change)

        # greška slanja ne poništava završenu promjenu.
        except (SMTPException, OSError):
            logger.exception("Sending the email change completion notification failed.")

            messages.warning(
                request,
                "Your email address and password were changed, but the notification to your previous email address could not be sent."
            )

        messages.success(
            request,
            # "Your email address has been successfully changed. Please log in again."

            #  poruka potvrđuje promjenu oba podatka.
            "Your email address and password have been successfully changed. Please log in again."
        )

        return redirect("login")

    # otvaranje linka prikazuje formu.
    # Ne sprema email, lozinku niti potvrdu zahtjeva.
    def get(self, request, token):
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        email_change = get_object_or_404(
            EmailChange.objects.select_related("user"),
            new_email_token_hash=token_hash,
        )

        if not email_change.is_active or email_change.cancelled_at or email_change.used_at or email_change.new_email_verified:
            messages.error(request, "This email change request is no longer active.")
            return redirect("home")

        if email_change.expires_at <= timezone.now():
            messages.error(request, "This email change request has expired.")
            return redirect("home")

        if not email_change.old_email_verified:
            messages.error(request, "Old email address has not been verified.")
            return redirect("home")

        user = email_change.user

        if not user.is_active:
            messages.error(request, "This account is inactive.")
            return redirect("home")

        if user.email.casefold() != email_change.old_email.casefold():
            messages.error(request, "This request no longer matches your current email address.")
            return redirect("home")

        # priprema praznu Django formu za novu lozinku.
        user.email = email_change.new_email
        form = SetPasswordForm(user=user)

        return render(request, "users/email_change_new_verify.html", {"form": form})




# otkazuje zahtjev prijavljenog korisnika.
class EmailChangeCancelView(LoginRequiredMixin, View):

    # otkazivanje se izvršava samo POST zahtjevom.
    def post(self, request):

        # pronalazi otvoren zahtjev ovog korisnika
        # i jednim upitom ga označava kao otkazan i neaktivan.
        cancelled = EmailChange.objects.filter(
            user=request.user,
            is_active=True,
            used_at__isnull=True,
            cancelled_at__isnull=True,
        ).update(
            is_active=False,
            cancelled_at=timezone.now(),
        )

        # obavještava korisnika o rezultatu.
        if cancelled:
            messages.success(request, "Your email change request has been cancelled.")
        else:
            messages.info(request, "You have no pending email change request to cancel.")

        return redirect("email_change")



# ponovno slanje linka
# ponovno šalje link za trenutni korak promjene emaila.
class EmailChangeResendView(LoginRequiredMixin, View):

    def post(self, request):
        # koristi isti brojač kao pokretanje zahtjeva.
        rate_limit_error = check_email_change_rate_limit(request.user)

        # odbija prečest pokušaj bez mijenjanja postojećeg tokena.
        if rate_limit_error:
            messages.error(request, rate_limit_error)
            return redirect("email_change")

        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        with transaction.atomic():
            # uzimamo samo zahtjev prijavljenog korisnika.
            # Zaključavamo zapis dok pripremamo novi token.
            email_change = EmailChange.objects.select_for_update().filter(user=request.user).first()

            if not email_change:
                messages.info(request, "You have no email change request. Please start a new request.")
                return redirect("email_change")

            if not email_change.is_active or email_change.cancelled_at or email_change.used_at or email_change.new_email_verified:
                messages.info(request, "This request is no longer active. Please start a new request.")
                return redirect("email_change")

            if email_change.expires_at <= timezone.now():
                email_change.is_active = False
                email_change.save(update_fields=["is_active"])

                messages.error(request, "This request has expired. Please start a new request.")
                return redirect("email_change")

            # zahtjev mora još odgovarati trenutnom emailu.
            user = get_user_model().objects.get(pk=email_change.user_id)

            if not user.is_active or user.email.casefold() != email_change.old_email.casefold():
                email_change.is_active = False
                email_change.save(update_fields=["is_active"])

                messages.error(request, "This request can no longer be continued.")
                return redirect("email_change")

            # biramo na koji email treba poslati link.
            send_to_new_email = email_change.old_email_verified

            if send_to_new_email:
                token_field = "new_email_token_hash"
            else:
                token_field = "old_email_token_hash"

            # pamtimo prethodni hash za slučaj greške slanja.
            previous_token_hash = getattr(email_change, token_field)

            # novi token zamjenjuje prethodni token ovog koraka.
            setattr(email_change, token_field, token_hash)
            email_change.save(update_fields=[token_field])

        try:
            # koristimo tvoje postojeće email servise.
            if send_to_new_email:
                send_new_email_change_confirmation(request, email_change, token)
            else:
                send_old_email_change_confirmation(request, email_change, token)

        except (SMTPException, OSError):
            logger.exception("Resending the email change confirmation failed.")

            # vraćamo prethodni hash ako slanje ne uspije.
            # Uslovi sprečavaju prepisivanje novijeg ili završenog zahtjeva.
            filters = {
                "pk": email_change.pk,
                "is_active": True,
                "old_email_verified": send_to_new_email,
                "new_email_verified": False,
                "used_at__isnull": True,
                "cancelled_at__isnull": True,
                token_field: token_hash,
            }

            EmailChange.objects.filter(**filters).update(**{token_field: previous_token_hash})

            messages.error(request, "The confirmation email could not be sent. Please try again.")
            return redirect("email_change")

        if send_to_new_email:
            messages.success(request, "A new confirmation link has been sent to your new email address.")
        else:
            messages.success(request, "A new confirmation link has been sent to your current email address.")

        return redirect("email_change")    




