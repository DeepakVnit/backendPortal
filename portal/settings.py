"""
Django settings for portal project.

Generated by 'django-admin startproject' using Django 2.0.

For more information on this file, see
https://docs.djangoproject.com/en/2.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/2.0/ref/settings/
"""

import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/2.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'hidyep)*f#r8f#n9sma2r4#7k^7xt=0_@ksuh6zc^^toa6#1z='

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['www.example.com', '127.0.0.1', 'localhost']


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'portalapp',

    'corsheaders',
    'rest_framework',
    # 'social_django',
    # 'rest_social_auth',

    # 'oauth2_provider',
    # 'rest_framework_social_oauth2',
    # 'rest_framework_mongoengine',
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

ROOT_URLCONF = 'portal.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                # 'social_django.context_processors.backends',
                # 'social_django.context_processors.login_redirect',
            ],
        },
    },
]

WSGI_APPLICATION = 'portal.wsgi.application'

# Google Login Integration
AUTHENTICATION_BACKENDS = (
    # 'social_core.backends.google.GoogleOAuth2',
    # 'rest_framework_social_oauth2.backends.DjangoOAuth2',
    'django.contrib.auth.backends.ModelBackend',
)

# SOCIAL_AUTH_RAISE_EXCEPTIONS = True
# SOCIAL_AUTH_URL_NAMESPACE = 'social'
# SOCIAL_AUTH_GOOGLE_OAUTH2_FIELDS = ['email', 'username']  # optional
# SOCIAL_AUTH_GOOGLE_OAUTH2_KEY = "248520527211-gd14a2gruou5jilapfi46ngj7eevtbi5"
# SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET = "qMFDAz10h_cjQ44xg1sB7toU"
# DRFSO2_URL_NAMESPACE = 'auth'

CSRF_COOKIE_SECURE = True
CORS_ORIGIN_ALLOW_ALL = True

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.AllowAny',
    ),
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'portalapp.backends.JWTAuthentication',
        'rest_framework_jwt.authentication.JSONWebTokenAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',

    ),

    'EXCEPTION_HANDLER': 'portalapp.exceptions.core_exception_handler',
    'NON_FIELD_ERRORS_KEY': 'error'
}

STATIC_URL = '/static/'
STATIC_ROOT = 'mystatic/'

MEDIA_ROOT = 'mymedia/'
MEDIA_URL = '/media/'

AUTH_USER_MODEL = 'portalapp.User'
LOGIN_REDIRECT_URL = '/authenticate/'

APPEND_SLASH = True
# Database
# https://docs.djangoproject.com/en/2.0/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'optimumSearch',
        'USER': 'root',
        'PASSWORD': '',
        'HOST': 'localhost',   # Or an IP Address that your DB is hosted on
        'PORT': '3306',
        'OPTIONS': {
            'sql_mode': 'traditional',
        }
    }
}


# Password validation
# https://docs.djangoproject.com/en/2.0/ref/settings/#auth-password-validators

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
# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'Asia/Kolkata'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/2.0/howto/static-files/
import datetime
JWT_AUTH = {
    'JWT_EXPIRATION_DELTA': datetime.timedelta(seconds=3000),
    'JWT_REFRESH_EXPIRATION_DELTA': datetime.timedelta(days=7),
}
