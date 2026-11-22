#models
from django.shortcuts import render
from django.views.generic.edit import CreateView 
from django.urls import reverse_lazy, reverse
from django.http import HttpResponse # za prikaz poruke nakon slanja emaila
from django.contrib.auth.tokens import default_token_generator # za generisanje tokena za verifikaciju email adrese
from django.shortcuts import redirect
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages
from django.core.cache import cache
from django.views.decorators.http import require_POST



# services
from .services.email_service import send_verification_email


#forms
from .forms.user_creation_form import RegisterForm

#models
from django.contrib.auth.models import User

# Create your views here.


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
