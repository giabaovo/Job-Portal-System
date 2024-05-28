import json
import requests
import pytz
import datetime
import cloudinary.uploader

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from django.http import HttpResponseNotFound, HttpResponseRedirect
from django.conf import settings
from django.core.exceptions import BadRequest
from django.db import transaction
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from drf_social_oauth2.views import TokenView, ConvertTokenView, RevokeTokenView
from oauth2_provider.models import get_access_token_model

from social_django.models import UserSocialAuth

from authentication.serializers import (
    JobSeekerRegisterSerializer,
    EmployerRegisterSerializer,
    CheckCredsSerializer,
    ForgotPasswordSerializer,
    ResetPasswordSerializer,
    UpdatePasswordSerializer,
    AvatarSerializer
)
from authentication.models import User, ForgotPasswordToken
from authentication.tokens_custom import email_verification_token

from helpers import helper

from configs import variable_response as var_res, variable_system as var_sys

from console.jobs import queue_mail, queue_auth

class CustomTokenView(TokenView):
    def post(self, request, *args, **kwargs):
        mutable_data = request.data.copy()
        role_name_input = mutable_data.get('role_name', None)
        if mutable_data['grant_type'] == 'password' and not role_name_input:
            return var_res.response_data(status=status.HTTP_400_BAD_REQUEST)
        
        request._request.POST = request._request.POST.copy()
        for key, value in mutable_data.items():
            request._request.POST[key] = value

        url, headers, body, stt = self.create_token_response(request._request)

        if stt == status.HTTP_200_OK:
            if mutable_data["grant_type"] == "password":
                body_data = json.loads(body)
                access_token = body_data.get("access_token")
                if access_token is not None:
                    token = get_access_token_model().objects.get(token=access_token)
                    role_name = token.user.role_name
                    if not role_name == role_name_input:
                        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST)
            return var_res.response_data(status=stt, data=json.loads(body))
        if stt == status.HTTP_400_BAD_REQUEST:
            email = mutable_data.get("username", None)
            password = mutable_data.get("password", "")

            user = User.objects.filter(email=email).first()
            if not user:
                return var_res.response_data(status=stt, errors={
                    "errorMessage": ["Email is incorrect"]
                })
            if not user.is_active:
                return var_res.response_data(status=stt, errors={
                    "errorMessage": [
                        "Your account has been disabled"
                        "Please contact our customer service department"]
                })
            if not user.check_password(password):
                return var_res.response_data(status=stt, errors={
                    "errorMessage": ["Incorrect password"]
                })

            return var_res.response_data(status=stt, errors={
                "errorMessage": ["An error occurred during login"]
            })
        else:
            return var_res.response_data(status=stt)
        

class CustomConvertTokenView(ConvertTokenView):
    def post(self, request, *args, **kwargs):
        try:
            mutable_data = request.data.copy()
            request._request.POST = request._request.POST.copy()
            for key, value in mutable_data.items():
                request._request.POST[key] = value

            url, headers, body, stt = self.create_token_response(request._request)
            if stt == status.HTTP_400_BAD_REQUEST:
                error_body = json.loads(body)
                error = error_body.get("error", "")
                error_description = error_body.get("error_description", "")
                if error == "invalid_grant" and error_description == "User inactive or deleted.":
                    return var_res.response_data(status=stt, errors={
                        "errorMessage": [
                            "The account logged in with this email has been disabled or no longer exists. "
                            "Please contact our customer service for assistance."
                        ]
                    })
            res_data = json.loads(body)
            res_data['backend'] = mutable_data["backend"]
            return var_res.response_data(status=stt, data=res_data)
        except BadRequest as ex:
            str_ex = str(ex)
            return var_res.response_data(
                status=status.HTTP_400_BAD_REQUEST,
                errors={"errorMessage": [str_ex]}
            )


class CustomRevokeTokenView(RevokeTokenView):
    def facebook_revoke_token(self, access_token):
        response = requests.delete(url=settings.SOCIAL_AUTH_FACEBOOK_OAUTH2_REVOKE_TOKEN_URL, headers={
            "Authorization": "Bearer {}".format(access_token)
        })
        if response.status_code == status.HTTP_200_OK:
            print(">>> Revoke facebook token success!")

    def google_revoke_token(self, access_token):
        pass


    def post(self, request, *args, **kwargs):
        
        mutable_data = request.data.copy()
        backend = mutable_data.pop("backend", None)
        request._request.POST = request._request.POST.copy()
        for key, value in mutable_data.items():
            request._request.POST[key] = value

        if backend and backend != "0" and backend != 'undefined':
            social_auth_usersocialauth = UserSocialAuth.objects\
                .filter(user=request.user, provider=backend).first()
            if social_auth_usersocialauth:
                extra_data = social_auth_usersocialauth.extra_data
                if extra_data["expires"] is None:
                    social_access_token = extra_data["access_token"]
                    if backend == "facebook":
                        self.facebook_revoke_token(social_access_token)
                    elif backend == "google-oauth2":
                        self.google_revoke_token(social_access_token)

        url, headers, body, status = self.create_revocation_response(request._request)
        response = Response(
            data=json.loads(body) if body else '', status=status if body else 200
        )

        for k, v in headers.items():
            response[k] = v
        return response
    

@api_view(http_method_names=['post'])
def check_creds(request):
    data = request.data
    res_data = {
        'exists': False,
        'email': '',
        'is_verify_email': False
    }

    serializer = CheckCredsSerializer(data=data)
    if not serializer.is_valid():
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
    
    email = serializer.data['email']
    role_name = serializer.data.get('role_name', '')

    user = User.objects.filter(email__iexact=email)
    if role_name:
        user = user.filter(role_name=role_name)

    res_data["email"] = email
    if user:
        user = user.first()
        res_data["exists"] = True
        if user.is_verify_email:
            res_data["is_verify_email"] = True

    return var_res.response_data(res_data)


@api_view(http_method_names=['post'])
def forgot_password(request):
    data = request.data
    serializer = ForgotPasswordSerializer(data=data)

    if not serializer.is_valid():
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
    
    email = serializer.validated_data.get('email')

    user = User.objects.filter(email=email).first()

    if user:
        try:
            now = datetime.datetime.now()
            now = now.astimezone(pytz.utc)

            tokens = ForgotPasswordToken.objects.filter(user=user, is_active=True, expired_at__gte=now)
            if tokens.exists():
                token = tokens.first()
                token_create_at = token.create_at
                if (now - token_create_at).total_seconds() < settings.TIME_AUTH['TIME_REQUIRED_FORGOT_PASSWORD']:
                    return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors={
                        "errorMessage": [
                            "You have just sent a request to send an email forgot your password."
                            "Please check your inbox or wait 2 minutes to resend the email"
                            ]
                    })
            with transaction.atomic():
                expired_at = now + datetime.timedelta(seconds=settings.TIME_AUTH['RESET_PASSWORD_EXPIRE_SECONDS'])

                access_token = urlsafe_base64_encode(force_bytes(user.pk))
                url = 'update-password/{}'.format(access_token)
                reset_password_url = helper.get_full_client_url(url)

                ForgotPasswordToken.objects.create(user=user, expired_at=expired_at, token=access_token)

                queue_mail.send_reset_password_email_task.delay([user.email], reset_password_url)

        except Exception as ex:
            helper.print_log_error('forgot_password', ex)
            return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return var_res.response_data(status=status.HTTP_200_OK)
    else:
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors={
            "errorMessage": ["This email is not in use, please register to join CatJob"]
        })


@api_view(http_method_names=['post'])
def reset_password(request):
    data = request.data
    serializer = ResetPasswordSerializer(data=data)

    if not serializer.is_valid():
        return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
    
    try:
        now = datetime.datetime.now()
        now = now.astimezone(pytz.utc)

        new_password = serializer.validated_data['new_password']
        token = serializer.validated_data['token']
        user_id = force_str(urlsafe_base64_decode(token))

        forgot_password_token = ForgotPasswordToken.objects.filter(user_id=user_id, token=token, is_active=True)
        if not forgot_password_token.exists():
            return var_res.response_data(
                status=status.HTTP_400_BAD_REQUEST,
                errors={'errorMessage': ['Sorry, it looks like the forgotten password confirmation link is invalid']}
            )
        else:
            forgot_password_token = forgot_password_token.first()
            if forgot_password_token.create_at < now:
                return var_res.response_data(
                    status=status.HTTP_400_BAD_REQUEST,
                    errors={'errorMessage': ['Sorry, it looks like the forgotten password confirmation link has expired']}
                )
            else:
                with transaction.atomic():
                    user = forgot_password_token.user
                    user.set_password(new_password)
                    user.save()
                    forgot_password_token.is_active = False
                    forgot_password_token.save()
                    user_role = user.role_name

                    redirect_login_url = settings.REDIRECT_LOGIN_CLIENT[user_role]
                    return var_res.response_data(data={'redirectLoginUrl': '/{}'.format(redirect_login_url)})
    except Exception as ex:
        helper.print_log_error('reset_oassword', ex)
        return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@api_view(http_method_names=['put'])
@permission_classes(permission_classes=[IsAuthenticated])
def change_password(request):
    try:
        data = request.data
        user = request.user

        serializer = UpdatePasswordSerializer(user, data=data, context={'user': user})
        if not serializer.is_valid():
            return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
        serializer.save()
    except Exception as ex:
        helper.print_log_error('change_password', ex)
        return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return var_res.response_data(status=status.HTTP_200_OK)


@api_view(http_method_names=['put', 'delete'])
@permission_classes(permission_classes=[IsAuthenticated])
def avatar(request):
    user = request.user

    if request.method == 'PUT':
        files = request.FILES
        serializer = AvatarSerializer(user, data=files)
        if not serializer.is_valid():
            return var_res.response_data(status=status.HTTP_400_BAD_REQUEST, errors=serializer.errors)
        try:
            serializer.save()
        except Exception as ex:
            helper.print_log_error('avatar put', ex)
            return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return var_res.response_data(status=status.HTTP_200_OK, data=serializer.data)
    elif request.method == 'DELETE':
        try:
            if user.avatar_public_id:
                avatar_delete_result = cloudinary.uploader.destroy(user.avatar_public_id)
                result = avatar_delete_result.get('result', '')
                if result != 'ok':
                    raise Exception('Something went wrong when delete user avatar')
                
            user.avatar_url = var_sys.AVATAR_DEFAULT['AVATAR']
            user.avatar_public_id = None
            user.save()

            if not user.has_company:
                queue_auth.update_avatar.delay(user.id, user.avatar_url)
        except Exception as ex:
            helper.print_log_error('avatar delete', ex)
            return var_res.response_data(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return var_res.response_data(status=status.HTTP_200_OK, data={
                'avatar_url': user.avatar_url
            })
    else:
        return var_res.response_data(status=status.HTTP_405_METHOD_NOT_ALLOWED)

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