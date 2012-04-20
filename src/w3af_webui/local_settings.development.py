#-*- coding: utf-8 -*-
import os.path
import sys

DEBUG = True
TEMPLATE_DEBUG = DEBUG

_PATH = os.path.abspath(os.path.dirname(__file__))
STATIC_ROOT = os.path.join(_PATH, 'static')
#MEDIA_ROOT = (os.path.join(_PATH, 'media'),)
LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        'console' : {
            'level': 'ERROR',
            'class':'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root' : {
        'handlers': ['console', ],
        'level': 'ERROR',
    },
}

test_flags = ['--with-django', '--with-freshen', 'test', 'jenkins', 'test_coverage']
IS_TEST = bool(filter(lambda x: x in sys.argv, test_flags))
if IS_TEST:
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': 'testing.db',
            'TEST_CHARSET': 'utf8',
        }
    }

SOUTH_TESTS_MIGRATE = False
SKIP_SOUTH_TESTS = True
