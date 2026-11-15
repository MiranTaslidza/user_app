#models
from django.shortcuts import render
from django.views.generic.edit import CreateView 
from django.urls import reverse_lazy


#forms
from .forms.user_creation_form import RegisterForm

#models


# Create your views here.


############# user CBV #######################
def home(request):
    return render(request, 'users/home.html')

#register
class RegisterView(CreateView):
    form_class = RegisterForm
    template_name = 'users/register.html'
    success_url = reverse_lazy('home')


