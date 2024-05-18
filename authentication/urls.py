from django.urls import path

from . import views

urlpatterns = [
    path('job-seeker/register/', views.job_seeker_register)
]
