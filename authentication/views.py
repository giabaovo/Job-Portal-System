from rest_framework import status
from rest_framework.decorators import api_view, permission_classes

from django.http import HttpResponseNotFound, HttpResponseRedirect
from django.conf import settings

from authentication.serializers import (
    JobSeekerRegisterSerializer,
    EmployerRegisterSerializer
)
from authentication.models import User
from authentication.tokens_custom import email_verification_token

from helpers import helper

from configs import variable_response as var_res, variable_system as var_sys

@api_view(http_method_names=['post'])
def job_seeker_register(request):
    data = request.data
    serializer = JobSeekerRegisterSerializer(data=data)
    if not serializer.is_valid():
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
    
    try:
        user = serializer.save()
        if user:
            # Sending Verify Email
            helper.send_verify_email(request, user)
    except Exception as ex:
        helper.print_log_error('job_seeker_register', ex)
        return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return var_res.response_data(status=status.HTTP_201_CREATED)

@api_view(http_method_names=['post'])
def employer_register(request):
    data = request.data
    serializer = EmployerRegisterSerializer(data=data)
    if not serializer.is_valid():
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
    
    try:
        user = serializer.save()

        if user:
            helper.send_verify_email(request, user)
    except Exception as ex:
        helper.print_log_error('employer_register', ex)
        return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return var_res.response_data(status=status.HTTP_201_CREATED)

@api_view(http_method_names=['get'])
def user_active(request, encode_data, token):
    if 'redirectLogin' not in request.GET:
        return HttpResponseNotFound()
    
    redirect_url = request.GET.get('redirectLogin')
    if redirect_url != settings.REDIRECT_LOGIN_CLIENT[var_sys.JOB_SEEKER] and \
            redirect_url != settings.REDIRECT_LOGIN_CLIENT[var_sys.EMPLOYER]:
        return HttpResponseNotFound()
    
    try:
        uid, expiration_time = helper.urlsafe_base64_decode_with_encode_data(encode_data)

        if uid is None or expiration_time is None:
            return HttpResponseRedirect(
                helper.get_full_client_url('{}/?errorMessage=Sorry, it looks like the email verification link is invalid'.format(redirect_url))
            )
        
        if not helper.check_expiration_time(expiration_time):
            return HttpResponseRedirect(
                helper.get_full_client_url('{}/?errorMessage=Sorry, it looks like the email verification link has expired'.format(redirect_url))
            )
        
        user = User.objects.get(pk=uid)
    except Exception as ex:
        user = None
        helper.print_log_error('user_active', ex)

    if user and email_verification_token.check_token(user, token):
        user.is_active = True
        user.is_verify_email = True
        user.save()

        noti_title = 'Welcome to CatJob! Get ready to explore and experience our system to find your dream job'
        if user.role_name == var_sys.EMPLOYER:
            noti_title = "Welcome to CatJob! Fast and convenient job referral system to find talent for your company!"

        helper.add_system_notification(
            'Welcome',
            noti_title,
            [user.id]
        )

        return HttpResponseRedirect(
            helper.get_full_client_url('{}/?successMessage=Email has been verified'.format(redirect_url))
        )
    else:
        return HttpResponseRedirect(
            helper.get_full_client_url('{}/?errorMessage=Sorry, it looks like the email verification link is invalid'.format(redirect_url))
        )