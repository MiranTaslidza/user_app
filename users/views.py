#models
from django.shortcuts import render
from django.views.generic.edit import CreateView 
from django.urls import reverse_lazy
from django.core.mail import send_mail # za slanje emaila
from django.conf import settings # za pristup postavkama iz settings.py
from django.http import HttpResponse # za prikaz poruke nakon slanja emaila
from django.contrib.auth.tokens import default_token_generator # za generisanje tokena za verifikaciju email adrese
from django.urls import reverse # za generisanje URL-a na osnovu imena rute
from django.utils.encoding import force_bytes # za kodiranje ID korisnika u base64 format
from django.utils.http import urlsafe_base64_encode # za kodiranje ID korisnika u base64 format na siguran način za URL
from django.shortcuts import redirect
from django.utils.http import urlsafe_base64_decode
from django.contrib import messages





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

# funkcija za slanje emaila
def send_verification_email(request, user): 
    uid = urlsafe_base64_encode(force_bytes(user.pk)) # kodiranje ID korisnika u base64 format kako bi se mogao sigurno koristiti u URL-u.
    token = default_token_generator.make_token(user) # generisanje tokena za verifikaciju korisnika. Token se koristi za potvrdu identiteta korisnika prilikom verifikacije email adrese.
    
    # kreiranje URL-a za verifikaciju email adrese. Koristi se funkcija reverse za generisanje URL-a na osnovu imena rute "verify_email" i prosleđuje se uid i token kao parametri.
    verification_path = reverse("verify_email", kwargs={"uidb64": uid, "token": token,},)
    
    # kreiranje punog URL-a za verifikaciju email adrese. Funkcija build_absolute_uri generiše apsolutni URL na osnovu relativnog puta verification_path. Ovaj URL će biti poslat korisniku u emailu kako bi mogao potvrditi svoju email adresu.
    verification_url = request.build_absolute_uri(verification_path)
    
    # kreiranje poruke za email verifikaciju. Poruka sadrži pozdrav korisniku, uputstvo da klikne na link za verifikaciju i sam link (verification_url). Takođe, uključuje napomenu da ako korisnik nije napravio račun, može zanemariti poruku.
    subject = "Email address confirmation"

    # kreiranje poruke za email verifikaciju. Poruka sadrži pozdrav korisniku, uputstvo da klikne na link za verifikaciju i sam link (verification_url). Takođe, uključuje napomenu da ako korisnik nije napravio račun, može zanemariti poruku.
    message = (
        f"Hello {user.username},\n\n"
        "Click the following link to verify your email address:\n\n"
        f"{verification_url}\n\n"
        "If you have not created this account, please ignore the message."
    )

    # send_mail je funkcija koja šalje email. Prima sledeće parametre: 
    send_mail(
        subject=subject, # subject: Naslov emaila.
        message=message, # message: Sadržaj emaila.
        from_email=settings.DEFAULT_FROM_EMAIL,  # from_email: Email adresa pošiljaoca, koja se uzima iz postavki (settings.DEFAULT_FROM_EMAIL).
        recipient_list=[user.email], # recipient_list: Lista primaoca, u ovom slučaju samo email adresa korisnika.
        fail_silently=False, # fail_silently: Ako je False, greške prilikom slanja emaila će biti prijavljene. Ako je True, greške će biti ignorisane.
    )
    
    messages.success(
        request,
        'A verification email has been sent. Please check your inbox and follow the link to verify your email address before signing in.'
    )


# funkcija za verifikaciju emaila
def verify_email(request, uidb64, token):
    try:
        # Dekodira ID korisnika iz URL-a
        uid = urlsafe_base64_decode(uidb64).decode()

        # Pronalazi korisnika u bazi
        user = User.objects.get(pk=uid)

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    # Provjerava da li korisnik postoji i da li je token ispravan
    if user is not None and default_token_generator.check_token(user, token):

        user.is_active = True
        user.save()
        
        messages.success(
            request,
            "Your email has been successfully verified. You can now log in."
        )

        return redirect('login')

    return HttpResponse("The verification link is invalid or has expired.")

