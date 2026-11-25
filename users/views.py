#models
from django.shortcuts import render
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
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.forms import SetPasswordForm
from uuid import uuid4
from users.models.profile_model import Profile
logger = logging.getLogger(__name__)
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, PasswordResetView, PasswordResetConfirmView, PasswordChangeView, PasswordChangeDoneView
from django.contrib.messages.views import SuccessMessageMixin
from smtplib import SMTPException



# services
from .services.email_service import send_verification_email, send_password_changed_email
from .services.google_oauth_service import get_google_authorization_url, exchange_code_for_token, verify_google_id_token

#forms
from .forms.user_creation_form import RegisterForm
from .forms.profile_form import ProfileForm
from .forms.profile_update import ProfileUpdateForm

#models
from django.contrib.auth.models import User

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

