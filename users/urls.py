from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', views.home, name='home'),
    path("register/", views.RegisterView.as_view(), name="user-register"), # registracija
    path('login/', auth_views.LoginView.as_view(template_name='users/login.html'), name="login"), # login
    path('logout/', LogoutView.as_view(next_page='/users/'), name='logout'), # logout
]