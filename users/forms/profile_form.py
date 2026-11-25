from django import forms
from ..models.profile_model import Profile
from django.utils import timezone

class ProfileForm(forms.ModelForm):
    class Meta:
        model = Profile
        fields = ['image', 'phone', 'bio', 'birth_date']
        widgets = {
            'image': forms.ClearableFileInput(attrs={'class': 'form-control', 'accept': 'image/*'}),
            'phone': forms.TextInput(attrs={'class': 'form-control', 'type': 'tel', 'autocomplete': 'tel', 'placeholder': '+387 61 123 456'}),
            'bio': forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Tell us a little about yourself...'}),
            'birth_date': forms.DateInput(format='%Y-%m-%d', attrs={'class': 'form-control', 'type': 'date', 'autocomplete': 'bday'}),
        }
    
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
                    'Morate imati najmanje 15 godina.'
                )

        return birth_date
    
    # smanjena veličina slike, da ne bude prevelika
    def clean_image(self):
        image = self.cleaned_data.get('image')

        if image and image.size > 5 * 1024 * 1024:
            raise forms.ValidationError(
                'Slika ne smije biti veća od 5 MB.'
            )

        return image

