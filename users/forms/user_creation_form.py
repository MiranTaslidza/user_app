from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError

class RegisterForm(UserCreationForm):
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ['username', 'first_name', 'last_name', 'email']
        
    # sakrivanje helper teksta za polja
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        for field in self.fields.values():
            field.help_text = ''
            field.widget.attrs['class'] = 'form-control'

    # dodavanje jedinstvenog email-a validacija email-a    
    def clean_email(self):
        email = self.cleaned_data.get('email', '').strip()

        if not email:
            raise ValidationError('Email is required.')

        if User.objects.filter(email__iexact=email).exists():
            raise ValidationError('A user with this email already exists.')

        return email
