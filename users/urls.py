from django.urls import path
from . import views
from django.contrib.auth.views import LogoutView

urlpatterns = [
    path('', views.home, name='home'),
    path("register/", views.RegisterView.as_view(), name="user-register"), # registracija
    path('login/', views.CustomLoginView.as_view(template_name='users/login.html'), name='login'), # login
    path('logout/', LogoutView.as_view(next_page='/users/'), name='logout'), # logout
    
    # url za  zaboravljen password
    path("password-reset/", views.CustomPasswordResetView.as_view(template_name="users/password_reset_form.html", email_template_name="users/password_reset_email.html", subject_template_name="users/password_reset_subject.txt"), name="password_reset"),
    path("reset/<uidb64>/<token>/", views.CustomPasswordResetConfirmView.as_view(template_name="users/password_reset_confirm.html"), name="password_reset_confirm" ),
    
    # promjena passworda
    path("change-password/", views.CustomPasswordChangeView.as_view(), name="password_change"),
    
    # promjena e-maila
    path("email-change/", views.EmailChangeView.as_view(), name="email_change"),
    path("email-change/old-verify/<str:token>/", views.EmailChangeOldVerifyView.as_view(), name="email_change_old_verify"), # verifikacija starog emaila
    path("email-change/new-verify/<str:token>/", views.EmailChangeNewVerifyView.as_view(), name="email_change_new_verify"), # verifikacija novog emaila
    path("email-change/cancel/", views.EmailChangeCancelView.as_view(), name="email_change_cancel"), # otkazivanje zahtjeva za promjenu e-maila
    path("email-change/resend/", views.EmailChangeResendView.as_view(), name="email_change_resend"), # ponovno slanje verifikacijskog linka za promjenu emaila
    


    # profile
    path('profile/', views.ProfileCreateView.as_view(), name='profile'), # kreiranje profila
    path('profile/<int:pk>/', views.ProfileDetailView.as_view(), name='profile_detail'), # uređivanje profila
    path('profile/<int:pk>/update/', views.ProfileUpdateView.as_view(), name='profile_update'), # uređivanje profila
    
    # verifikacija maila
    path("verify-email/<uidb64>/<token>/", views.verify_email, name="verify_email"), # verifikacija emaila
    path("verification-email-sent/", views.verification_email_sent,name="verification_email_sent"), 
    path('resend-verification-email/', views.resend_verification_email, name='resend_verification_email'), # ponovno slanje verifikacijskog linka
    
    #google reg login
    path("google/login/", views.GoogleLoginView.as_view(), name="google_login"), # google login
    path('google/callback/', views.GoogleCallbackView.as_view(), name='google_callback'),
    path('set-password/', views.SetInitialPasswordView.as_view(), name='set_initial_password'),

]   
