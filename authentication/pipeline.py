from django.core.exceptions import BadRequest

from configs import variable_system as var_sys

from helpers import helper

from .models import User


def custom_social_user(strategy, details, user=None, *args, **kwargs):
    if user:
        # User is already authenticated, do nothing
        return {'is_new': False}

    # Check if the user exists in your local database based on their email address
    email = details.get('email')
    if email:
        try:
            user = User.objects.get(email=email)
            # check if the current user is an employer or not
            if user.role_name == var_sys.EMPLOYER:
                raise BadRequest(
                    'The social network account email you just linked already exists, please log in with another account.'
                )
            return {
                'is_new': False,
                'user': user
            }
        except User.DoesNotExist:
            pass

    return {
        'is_new': True,
        'user': None
    }


def custom_create_user(strategy, backend, user=None, *args, **kwargs):
    if user:
        return {'is_new': False}

    full_name = kwargs.get('response').get('name')
    email = kwargs.get('response').get('email')

    if not email:
        raise Exception('Email is required for registration')

    user = User.objects.get(email=email)

    if not user:
        user = User.objects.create_user(
            email=email,
            full_name=full_name,
            is_active=True,
            is_verify_email=True
        )

    #send noti welcome
    helper.add_system_notification(
        "Welcome",
        "Welcome to CatJob! Get ready to explore and experience our system to find your dream job",
        [user.id]
    )

    return {'is_new': True, 'user': user}