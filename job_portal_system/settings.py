import firebase_admin

from firebase_admin import credentials

from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-)nsjzyg#5mv739qw2hu=!_=64fmocnw9zrt$m%)k$@%pa5l1o9'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    # Third-party apps
    'rest_framework',
    'drf_yasg',
    'oauth2_provider',
    'social_django',
    'drf_social_oauth2',

    # Internal apps
    'authentication',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'job_portal_system.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [ BASE_DIR / 'job_portal_system/templates',
                  BASE_DIR / 'job_portal_system/templates/emails' ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
            ],
        },
    },
]

WSGI_APPLICATION = 'job_portal_system.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

STATIC_URL = 'static/'

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

AUTH_USER_MODEL = 'authentication.User'

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'oauth2_provider.contrib.rest_framework.OAuth2Authentication',
        'drf_social_oauth2.authentication.SocialAuthentication',
    )
}

OAUTH2_PROVIDER = {
    'SCOPES': {
        'read': 'Read scope',
        'write': 'Write scope',
    },
    'CLIENT_ID_GENERATOR_CLASS': 'oauth2_provider.generators.ClientIdGenerator',
    'ACCESS_TOKEN_EXPIRE_SECONDS': 100000
}

AUTHENTICATION_BACKENDS = (
    # Facebook OAuth2
    'social_core.backends.facebook.FacebookAppOAuth2',
    'social_core.backends.facebook.FacebookOAuth2',

    # Google OAuth2
    'social_core.backends.google.GoogleOAuth2',

    # drf_social_oauth2
    'drf_social_oauth2.backends.DjangoOAuth2',
    # Django
    'django.contrib.auth.backends.ModelBackend',
)

# FaceBook social configurations

SOCIAL_AUTH_FACEBOOK_DIALOG_URL = 'https://www.facebook.com/v15.0/dialog/oauth/'
SOCIAL_AUTH_FACEBOOK_OAUTH2_REVOKE_TOKEN_URL = 'https://graph.facebook.com/v15.0/me/permissions'
SOCIAL_AUTH_FACEBOOK_KEY = '966075208326212'
SOCIAL_AUTH_FACEBOOK_SECRET = '8bfc83531b5e369bb6587ed07da5bc94'

# GOOGLE
# Google configuration
SOCIAL_AUTH_GOOGLE_OAUTH2_URL = 'https://accounts.google.com/o/oauth2/auth'
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = '860723762850-ja6s9v9f1tp474ic32o8lb5g8d24t60k.apps.googleusercontent.com'
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = 'google-app-secret'

# Define SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE to get extra permissions from Google.
SOCIAL_AUTH_GOOGLE_OAUTH2_SCOPE = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
]

# Define SOCIAL_AUTH_FACEBOOK_SCOPE to get extra permissions from Facebook.
# Email is not sent by default, to get it, you must request the email permission.
SOCIAL_AUTH_FACEBOOK_SCOPE = ['email']
SOCIAL_AUTH_FACEBOOK_PROFILE_EXTRA_PARAMS = {
    'fields': 'id, name, email, first_name, last_name'
}

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.auth_allowed',
    'authentication.pipeline.custom_create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details'
)

REDIRECT_LOGIN_CLIENT = {
    "JOB_SEEKER": "job-seeker-login",
    "EMPLOYER": "employer-login"
}

TIME_AUTH = {
    "VERIFY_EMAIL_LINK_EXPIRE_SECONDS": 7200,
    "RESET_PASSWORD_EXPIRE_SECONDS": 7200,
    "TIME_REQUIRED_FORGOT_PASSWORD": 120
}

# SERVICE_REDIS_HOST = config('SERVICE_REDIS_HOST')
# SERVICE_REDIS_PORT = config('SERVICE_REDIS_PORT', cast=int)
# SERVICE_REDIS_USERNAME = config('SERVICE_REDIS_USERNAME')
# SERVICE_REDIS_PASSWORD = config('SERVICE_REDIS_PASSWORD')
# SERVICE_REDIS_DB = config('SERVICE_REDIS_DB', cast=int)

# CELERY_BROKER_URL = "redis://{}:{}@{}:{}/{}".format(SERVICE_REDIS_USERNAME, SERVICE_REDIS_PASSWORD, SERVICE_REDIS_HOST, SERVICE_REDIS_PORT, SERVICE_REDIS_DB)
CELERY_BROKER_URL = "redis://127.0.0.1:6379"
CELERY_RESULT_BACKEND = "redis://127.0.0.1:6379"
# CELERY_RESULT_BACKEND = "redis://{}:{}@{}:{}/{}".format(SERVICE_REDIS_USERNAME, SERVICE_REDIS_PASSWORD, SERVICE_REDIS_HOST, SERVICE_REDIS_PORT, SERVICE_REDIS_DB)
CELERY_TASK_SERIALIZER = 'json'
CELERY_RESULT_SERIALIZER = 'json'
CELERY_ACCEPT_CONTENT = ['json']
CELERY_TIMEZONE = 'Asia/Ho_Chi_Minh'

# EMAIL_HOST = config('EMAIL_HOST')
# EMAIL_PORT = config('EMAIL_PORT', cast=int)
# EMAIL_HOST_USER = config('EMAIL_HOST_USER')
# EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD')
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_USE_TLS = True
# DEFAULT_FROM_EMAIL = EMAIL_HOST_USER

EMAIL_HOST = 'sandbox.smtp.mailtrap.io'
EMAIL_HOST_USER = '7b2812e6bc5861'
EMAIL_HOST_PASSWORD = 'b0f65565a24461'
DEFAULT_FROM_EMAIL = 'testing@giabaovo.com'
EMAIL_PORT = '2525'
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_USE_TLS = True

DOMAIN_CLIENT = {
    "local": "http://localhost:3000/",
    # "production": config('WEB_CLIENT_URL'),
}

# APP_ENVIRONMENT = config('APP_ENV')
APP_ENVIRONMENT = 'local'

FIREBASE_CONFIG = BASE_DIR / 'configs/firebase_config.json'

cred = credentials.Certificate(FIREBASE_CONFIG)
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://django-job-portal-a6113-default-rtdb.asia-southeast1.firebasedatabase.app/'
})