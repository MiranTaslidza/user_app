from django import forms
from django.contrib.auth.models import User
from .profile_form import ProfileForm
from django.db import transaction # ovo je potrebno za spremanje korisnika i profila u istoj transakciji

class ProfileUpdateForm(ProfileForm):
    # validacija polja iz User modela
    username = forms.CharField(max_length=150, validators=User._meta.get_field('username').validators,) 
    first_name = forms.CharField(max_length=150, required=False)
    last_name = forms.CharField(max_length=150, required=False)

    class Meta(ProfileForm.Meta):
        fields = ['username', 'first_name', 'last_name'] + ProfileForm.Meta.fields

    # popunjavanja polja sa postoječim podatcima
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        user = self.instance.user
        self.initial.update({
            'username': user.username,
            'first_name': user.first_name,
            'last_name': user.last_name,
        })

    # provjerava da li korisničko ime več postoji ukoliko ne postoji  njenja ga
    def clean_username(self):
        username = User.normalize_username(
            self.cleaned_data['username']
        )

        exists = User.objects.filter(
            username=username,
        ).exclude(pk=self.instance.user_id).exists()

        if exists:
            raise forms.ValidationError(
                'A user with this username already exists.'
            )

        return username

    # spremanje svih podataka u 2 različira modela
    # spremanje korisnika, profila i svih adresa
    def save(self, commit=True):
        profile = super().save(commit=False)
        user = profile.user

        user.username = self.cleaned_data['username']
        user.first_name = self.cleaned_data['first_name']
        user.last_name = self.cleaned_data['last_name']

        if commit:
            with transaction.atomic():
                #  zaključavamo korisnika prije spremanja.
                User.objects.select_for_update().get(pk=user.pk)

                user.save()
                profile.save()

                #  naslijeđeno spremanje svih adresa.
                self.save_addresses()

                self.save_m2m()

        return profile

