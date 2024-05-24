from django.urls import path, include

from . import views

urlpatterns = [
    path('token/', views.CustomTokenView.as_view()),
    path('convert-token/', views.CustomConvertTokenView.as_view()),
    path('revoke-token/', views.CustomRevokeTokenView.as_view()),
    path('', include('drf_social_oauth2.urls', namespace='drf')),

    path('check-creds/', views.check_creds),

    path('forgot-password/', views.forgot_password),
    path('reset-password/', views.reset_password),
    path('change-password/', views.change_password),

    path('job-seeker/register/', views.job_seeker_register),
    path('employer/register/', views.employer_register),

    path('active-email/<str:encode_data>/<str:token>/', views.user_active)
]
