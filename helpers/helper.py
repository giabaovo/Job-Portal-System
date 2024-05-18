import time

from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes

from authentication.tokens_custom import email_verification_token

from console.jobs import queue_mail

from datetime import datetime

def print_log_error(func_name, error):
    print('>>> ERROR [{}][{}] >> {}'.format(datetime.now(), func_name, error))

def urlsafe_base64_encode_with_expires(data, expires_in_seconds):
    base64_data = urlsafe_base64_encode(force_bytes(data))

    current_time = int(time.time())
    expire_time = current_time + expires_in_seconds
    base64_time = urlsafe_base64_encode(force_bytes(expire_time))

    encode_data = '{}|{}'.format(base64_data, base64_time)

    return encode_data

def send_verify_email(request, user):
    user_role = user.role_name
    redirect_login = settings.REDIRECT_LOGIN_CLIENT[user_role]

    encode_data = urlsafe_base64_encode_with_expires(
        user.pk, settings.TIME_AUTH['VERIFY_EMAIL_LINK_EXPIRE_SECONDS']
    )
    token = email_verification_token.make_token(user=user)
    url_path = 'api/auth/active-email/{}/{}/?redirectLogin={}'.format(encode_data, token, redirect_login)

    protocol = 'https' if request.is_secure() else 'http'
    domain = request.META['HTTP_HOST']

    data = {
        'confirm_email_url': '{}://{}/{}'.format(protocol, domain, url_path),
        'confirm_email_deeplink': None
    }

    queue_mail.send_verify_email_task.delay(to=[user.email], data=data)


