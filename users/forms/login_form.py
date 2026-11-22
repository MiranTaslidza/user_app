from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db.models import Q

class LoginForm(AuthenticationForm):
    email_not_verified = False

    def clean(self):
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

                if (
                    user is not None
                    and not user.is_active
                    and user.check_password(password)
                ):
                    self.email_not_verified = True
                    self.request.session['verification_user_id'] = user.pk

                    raise ValidationError(
                        'Email not verified. Confirm your email before signing up.',
                        code='email_not_verified',
                    )

            raise

