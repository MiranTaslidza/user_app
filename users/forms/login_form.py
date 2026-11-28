from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db.models import Q
from django.utils import timezone
from ..models.profile_model import Profile

class LoginForm(AuthenticationForm):
    email_not_verified = False
    # preko ove oznake prikazuje dugme za aktivaciju.
    account_deactivated = False


    def clean(self):
        self.email_not_verified = False
        # resetujemo oznaku za svaki pokušaj prijave.
        self.account_deactivated = False
        # račun za aktivaciju pri novom pokušaju prijave.
        self.request.session.pop('account_reactivation_request', None)

        try:
            return super().clean()

        except ValidationError:
            username = self.cleaned_data.get('username')
            password = self.cleaned_data.get('password')

            if username and password:
                try:
                    user = User.objects.get(
                        Q(username=username) |
                        Q(email__iexact=username)
                    )
                except (User.DoesNotExist, User.MultipleObjectsReturned):
                    user = None

                # prvo provjeravamo lozinku.
                if user is not None and user.check_password(password):
                    account_deactivated = Profile.objects.filter(
                        user_id=user.pk,
                        deactivated_at__isnull=False,
                    ).exists()

                    if account_deactivated:
                        # lozinka je provjerena i račun je deaktiviran.
                        self.account_deactivated = True
                        
                        # pamtimo račun nakon provjere tačne lozinke.
                        self.request.session['account_reactivation_request'] = {
                            'user_id': user.pk,
                            'verified_at': timezone.now().timestamp(),
                            'email': user.email,
                            'auth_hash': user.get_session_auth_hash(),
                        }


                        if self.request.session.get('verification_user_id') == user.pk:
                            self.request.session.pop('verification_user_id', None)

                        raise ValidationError(
                            'This account has been deactivated.',
                            code='account_deactivated',
                        )

                    # verifikaciju tražimo samo ako
                    # račun nije deaktiviran, ali je neaktivan.
                    if not user.is_active:
                        self.email_not_verified = True
                        self.request.session['verification_user_id'] = user.pk

                        raise ValidationError(
                            'Email not verified. Confirm your email before signing up.',
                            code='email_not_verified',
                        )

            raise

