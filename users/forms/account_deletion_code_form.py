from django import forms

class AccountDeletionCodeForm(forms.Form):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Nazivi odgovaraju postojećim poljima u HTML-u:
        # code_1, code_2, ... code_6.
        for number in range(1, 7):
            self.fields[f'code_{number}'] = forms.RegexField(
                regex=r'\A[0-9]\Z',
                min_length=1,
                max_length=1,
                required=True,
                error_messages={
                    'required': 'Enter all six digits.',
                    'invalid': 'Enter digits only.',
                    'min_length': 'Enter one digit per field.',
                    'max_length': 'Enter one digit per field.',
                },
            )

    def clean(self):
        cleaned_data = super().clean()

        # Spajamo cifre samo ako je svih šest polja ispravno.
        field_names = [
            f'code_{number}'
            for number in range(1, 7)
        ]

        if all(name in cleaned_data for name in field_names):
            cleaned_data['code'] = ''.join(
                cleaned_data[name]
                for name in field_names
            )

        return cleaned_data

