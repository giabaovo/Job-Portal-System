import time

from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str

from authentication.tokens_custom import email_verification_token

from console.jobs import queue_mail, queue_notification

from configs import variable_system as var_sys

from datetime import datetime

def print_log_error(func_name, error):
    print('>>> ERROR [{}][{}] >> {}'.format(datetime.now(), func_name, error))

def get_full_client_url(url):
    app_env = settings.APP_ENVIRONMENT

    return settings.DOMAIN_CLIENT[app_env] + url

def check_expiration_time(expiration_time):
    return expiration_time - int(time.time()) > 0

def urlsafe_base64_encode_with_expires(data, expires_in_seconds):
    base64_data = urlsafe_base64_encode(force_bytes(data))

    current_time = int(time.time())
    expire_time = current_time + expires_in_seconds
    base64_time = urlsafe_base64_encode(force_bytes(expire_time))

    encode_data = '{}|{}'.format(base64_data, base64_time)

    return encode_data

def urlsafe_base64_decode_with_encode_data(encode_data):
    try:
        encode_data_split = str(encode_data).split('|')

        data = force_str(urlsafe_base64_decode(encode_data_split[0]))
        expiration_time = force_str(urlsafe_base64_decode(encode_data_split[1]))

        return data, int(expiration_time) 
    except:
        return None, None

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

def add_system_notification(title, content, user_id_list):
    try:
        type_name = var_sys.NOTIFICATION_TYPE['SYSTEM']

        queue_notification.add_notification_to_user.delay(title=title, content=content, type_name=type_name, user_id_list=user_id_list)
    except Exception as ex:
        print_log_error('add_system_notification', ex)