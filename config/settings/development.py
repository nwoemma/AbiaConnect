from .base import *

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ['127.0.0.1', '10.0.2.1']

# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'abia2025',
        'USER': 'abia_user',
        'PASSWORD': 'BYABPZ9xPxY7U3rsamblVnOtnyKSEao9',
        'HOST': 'dpg-d0otn1ruibrs7384a9og-a.frankfurt-postgres.render.com',
        'PORT': '5432',
        # Add this line if your host requires SSL
        'OPTIONS': {
            'sslmode': 'require',
        },
    }
}
#STATIC_ROOT = BASE_DIR/ 'static'


STATICFILES_DIRS = [
    BASE_DIR/ "static", "./static/",
]


REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    # ← ADD THIS LINE
    'DEFAULT_SCHEMA_CLASS': 'drf_spectacular.openapi.AutoSchema',
}