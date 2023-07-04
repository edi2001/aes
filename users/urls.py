from django.urls import path
from .views import RegisterView,LoginView,UserView,LogoutView,PasswordTokenCheckAPI,RequestPasswordResetEmail
urlpatterns = [
    path('register',RegisterView.as_view()),
    path('login',LoginView.as_view()),
    path('user',UserView.as_view()),
    path('logout',LogoutView.as_view()),
    path('request-reset-email/',RequestPasswordResetEmail.as_view(),name='request-reset-email'),
    path('password-reset/<uidb64>/<token>/',PasswordTokenCheckAPI.as_view(),name='password-reset-confirm')
]


