from django.urls import path

from .views import RegisterUserView, GetUsersView, GetUserDetailView, LoginAuthToken, IsLoginView, ChangePasswordView, \
    SendPasswordResetEmailView, UserPasswordResetView, SendEmailVerificationCodeView, UpdateProfileView

urlpatterns = [
    path("register/", RegisterUserView.as_view()),
    path("update-profile/", UpdateProfileView.as_view()),
    path("verify-email/", SendEmailVerificationCodeView.as_view()),
    path("users/", GetUsersView.as_view()),
    path("user/<int:pk>/", GetUserDetailView.as_view()),
    path("login/", LoginAuthToken.as_view()),
    path("is-logged-in/", IsLoginView.as_view()),
    path("change-password/", ChangePasswordView.as_view()),
    path("send-reset-password-email/", SendPasswordResetEmailView.as_view()),
    path("reset-password/<uid>/<token>/", UserPasswordResetView.as_view())
]
