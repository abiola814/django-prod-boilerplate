from django.urls import path
from . import views
from django.http.response import JsonResponse


def homepage(request):
    return JsonResponse({"message": "Welcome to Django (Backend)"})


app_name = "home"

urlpatterns = [
    path('', homepage),
    path('create-user', views.CreateUserAPIView.as_view(), name="create-user"),
    path('confirm-otp', views.ConfirmOTPView.as_view(), name="confirm-otp"),
    path('request-otp', views.RequestOTPView.as_view(), name="request-otp"),
    path('change-password', views.ChangePasswordView.as_view(), name="change-password"),
    path('forgot-password', views.ForgotPasswordView.as_view(), name="forgot-password"),

    # Dashboard
    path('login', views.LoginAPIView.as_view(), name="login"),

    # Audit
    path('audit', views.AuditAPIView.as_view(), name="audit"),

 

]

