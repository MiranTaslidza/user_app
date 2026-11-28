from django.db import models
from django.contrib.auth.models import User

def profile_image_path(instance, filename):
    user_id = instance.user_id
    return f'picture/profile_picture/{user_id}/{filename}'

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    image = models.ImageField(upload_to=profile_image_path, blank=True, null=True) # slika
    phone = models.CharField(max_length=30, blank=True)
    bio = models.TextField(blank=True)
    birth_date = models.DateField(null=True, blank=True)
    
    # Vrijeme deaktivacije računa; prazno znači da nije deaktiviran.
    deactivated_at = models.DateTimeField(null=True, blank=True)
    # Hash tokena za potvrdu deaktivacije; originalni token šaljemo emailom.
    deactivation_token_hash = models.CharField(max_length=64, unique=True, null=True, blank=True)

    def __str__(self):
        return self.user.username

