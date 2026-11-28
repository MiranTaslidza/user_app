from django import forms
from django.contrib.auth import get_user_model
from django.forms import BaseInlineFormSet, inlineformset_factory
from ..models.address_model import Address

class AddressForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field in self.fields.values():
            field.widget.attrs['class'] = (
                'form-check-input' if isinstance(field.widget, forms.CheckboxInput)
                else 'form-control'
            )

    class Meta:
        model = Address
        fields = ['label', 'country', 'city', 'postal_code', 'street', 'house_number', 'address_line_2', 'is_default']

        labels = {
            'label': 'Address name',
            'country': 'Country',
            'city': 'City',
            'postal_code': 'Postal code',
            'street': 'Street',
            'house_number': 'House number',
            'address_line_2': 'Apartment, floor or additional details',
            'is_default': 'Use as my default address',
        }

# zajednička provjera svih unesenih adresa.
class BaseAddressFormSet(BaseInlineFormSet):
    def clean(self):
        super().clean()

        if any(self.errors):
            return

        default_count = 0

        for form in self.forms:
            # Prazne nove forme i adrese označene za brisanje preskačemo.
            if not form.cleaned_data or form.cleaned_data.get('DELETE'):
                continue

            if form.cleaned_data.get('is_default'):
                default_count += 1

        if default_count > 1:
            raise forms.ValidationError(
                'Choose only one default address.'
            )

# grupa adresnih formi povezana s jednim korisnikom.
AddressFormSet = inlineformset_factory(
    get_user_model(),
    Address,
    form=AddressForm,
    formset=BaseAddressFormSet,
    extra=1,
    can_delete=True,
)

