from django import forms
from ..models.profile_model import Profile
from django.utils import timezone

#  grupa adresnih formi i zajedničko spremanje.
from .address_form import AddressFormSet
from django.contrib.auth import get_user_model
from django.db import transaction

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['image', 'phone', 'bio', 'birth_date']
        widgets = {
            'birth_date': forms.DateInput(
                format='%Y-%m-%d',
                attrs={'type': 'date', 'class': 'form-control', 'autocomplete': 'bday'},
            ),
        }

    # profil dobija grupu korisnikovih adresa.
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.address_formset = AddressFormSet(
            data=self.data if self.is_bound else None,
            files=self.files if self.is_bound else None,
            instance=self.instance.user,
            prefix=self.add_prefix('addresses'),
        )

    # da osoba mlađa od 15 go ne može napraviti profil
    def clean_birth_date(self):
        birth_date = self.cleaned_data.get('birth_date')

        if birth_date:
            today = timezone.localdate()

            age = today.year - birth_date.year
            if (today.month, today.day) < (birth_date.month, birth_date.day):
                age -= 1

            if age < 15:
                raise forms.ValidationError(
                    # 'Morate imati najmanje 15 godina.'
                    #  poruka korisniku na engleskom.
                    'You must be at least 15 years old.'
                )

        return birth_date

    # provjera veličine slike
    def clean_image(self):
        image = self.cleaned_data.get('image')

        if image and image.size > 5 * 1024 * 1024:
            raise forms.ValidationError(
                # 'Slika ne smije biti veća od 5 MB.'
                #  poruka korisniku na engleskom.
                'The image must not exceed 5 MB.'
            )

        return image

    # ne spremamo profil ako adrese imaju grešku.
    def clean(self):
        cleaned_data = super().clean()

        if not self.address_formset.is_valid():
            raise forms.ValidationError(
                'Please correct the errors in your addresses.'
            )

        return cleaned_data

    # spremanje novih adresa, izmjena i brisanja.
    def save_addresses(self):
        with transaction.atomic():
            # Promjene adresa istog korisnika izvršavamo redom.
            get_user_model().objects.select_for_update().get(
                pk=self.instance.user_id,
            )

            self.address_formset.save()

            # Izabranu zadanu adresu ostavljamo kao jedinu zadanu.
            for address_form in self.address_formset.forms:
                if not address_form.cleaned_data or address_form.cleaned_data.get('DELETE'):
                    continue

                if address_form.cleaned_data.get('is_default'):
                    default_address = address_form.instance

                    self.instance.user.addresses.exclude(
                        pk=default_address.pk,
                    ).filter(is_default=True).update(is_default=False)

                    self.instance.user.addresses.filter(
                        pk=default_address.pk,
                    ).update(is_default=True)

                    break

    # profil i sve adrese spremamo zajedno.
    def save(self, commit=True):
        profile = super().save(commit=False)

        if commit:
            with transaction.atomic():
                get_user_model().objects.select_for_update().get(
                    pk=profile.user_id,
                )

                profile.save()
                self.save_addresses()
                self.save_m2m()

        return profile

