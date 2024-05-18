from django.core.mail import EmailMultiAlternatives
from django.conf import settings

def send_mail(subject, text_content, email_html, to=None, cc=None, bcc=None):
    email = EmailMultiAlternatives(
        subject,
        text_content,
        from_email=settings.EMAIL_HOST_USER,
        to=to,
        cc=cc,
        bcc=bcc
    )

    email.attach_alternative(email_html, 'text/html')
    return email.send()