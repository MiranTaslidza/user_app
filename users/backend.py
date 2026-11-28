from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.db.models import Q
from .models.profile_model import Profile

class UsernameOrEmailBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        if username is None or password is None:
            return None

        User = get_user_model()

        try:
            user = User.objects.get(
                Q(username=username) | Q(email__iexact=username)
            )
        except User.DoesNotExist:
            User().set_password(password)
            return None
        except User.MultipleObjectsReturned:
            return None

        if user.check_password(password) and self.user_can_authenticate(user):
            return user

        return None
    
    # provjerava aktivnost i deaktivaciju računa.
    def user_can_authenticate(self, user):
        # Zadržavamo Django zabranu prijave neaktivnom korisniku.
        if not super().user_can_authenticate(user):
            return False

        # Deaktiviran račun odbijamo čak i ako mu je is_active=True.
        account_deactivated = Profile.objects.filter(
            user_id=user.pk,
            deactivated_at__isnull=False,
        ).exists()

        return not account_deactivated


