from django import forms

class AccountDeactivationForm(forms.Form):
    confirm = forms.BooleanField(
        label=(
            'I understand that deactivating my account will '
            'all my applications will be terminated.'
        ),
        required=True,
        error_messages={
            'required': 'Confirm that you want to request account deactivation.',
        },
    )

