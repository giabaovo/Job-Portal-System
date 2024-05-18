from celery import shared_task

from django.template.loader import render_to_string
from django.utils.html import strip_tags

from configs import variable_system as var_sys

from helpers import utils

from datetime import datetime

@shared_task
def send_verify_email_task(to, data=None, cc=None, bcc=None):
    if data is None:
        data = {}

    subject = 'Verify email'

    data["my_email"] = var_sys.COMPANY_INFO["EMAIL"]
    data["my_phone"] = var_sys.COMPANY_INFO["PHONE"]
    data["my_logo_link"] = var_sys.COMPANY_INFO["DARK_LOGO_LINK"]
    data["my_address"] = var_sys.COMPANY_INFO["ADDRESS"]
    data["now"] = datetime.now().date().strftime(var_sys.DATE_TIME_FORMAT["dmY"])

    email_html = render_to_string('verify-email.html', data)
    text_content = strip_tags(email_html)
    sent = utils.send_mail(subject, text_content, email_html, to)

    if not sent:
        return 'Email verify sent failed'
    return 'Email verify sent successfully'

