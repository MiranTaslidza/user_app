from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView
from django.contrib.auth.forms import AuthenticationForm

AuthenticationForm.error_messages = {
    **AuthenticationForm.error_messages,
    'invalid_login': (
        'Login failed. Check username or email and password '
        'and have you confirmed your email address.'
    ),
}


urlpatterns = [
    path('', views.home, name='home'),
    path("register/", views.RegisterView.as_view(), name="user-register"), # registracija
    path('login/', auth_views.LoginView.as_view(template_name='users/login.html'), name="login"), # login
    path('logout/', LogoutView.as_view(next_page='/users/'), name='logout'), # logout
    
    # verifikacija maila
    #path('send_email/', views.send_verification_email, name='send_email'), # slanje emaila
    path("verify-email/<uidb64>/<token>/", views.verify_email, name="verify_email"), # verifikacija emaila
    
]