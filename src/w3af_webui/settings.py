#-*- coding: utf-8 -*-
import os.path
from datetime import timedelta
from django.utils.translation import ugettext_lazy as _

ADMINS = (
     ('Your Name', 'your_mail@example.ru'),
)

MANAGERS = ADMINS

#CREATE USER w3af_webui@localhost IDENTIFIED BY "w3af_webui";
#CREATE DATABASE w3af_webui CHARACTER SET utf8;
#GRANT ALL ON w3af_webui.* TO w3af_webui@localhost;
DATABASES = {
    'default': {
        'ENGINE'   : 'django.db.backends.mysql',
        'NAME'     : 'w3af_webui',
        'USER'     : 'w3af_webui',
        'PASSWORD' : 'w3af_webui',
        'HOST'     : '',
        'PORT'     : '3306',
        'OPTIONS'  : { 'init_command': 'SET storage_engine=INNODB;' },
    }
}

# Local time zone for this installation. Choices can be found here:
# http://en.wikipedia.org/wiki/List_of_tz_zones_by_name
# although not all choices may be available on all operating systems.
# On Unix systems, a value of None will cause Django to use the same
# timezone as the operating system.
# If running in a Windows environment this must be set to the same as your
# system time zone.
TIME_ZONE = 'Europe/Moscow'

LANGUAGES = (
    ('ru', _('Russian')),
    ('en', _('English')),
)

NOTIFY_MODULES = (
#   (_('Notification name'), 'string_id',  'module'), # example
    {'label': _('None'), 'id': 'None', 'module': ''}, # status number 1 set as default
    {'label': _('e-mail'), 'id': 'Mail', 'module': 'w3af_webui.notification.send_mail'},
)
NOTIFY_STATUS = list((ind, value['label'])
                     for ind, value in enumerate(NOTIFY_MODULES))

_PATH = os.path.abspath(os.path.dirname(__file__))
LOCALE_PATHS = (os.path.join(_PATH, 'locale'),)
# Language code for this installation. All choices can be found here:
# http://www.i18nguy.com/unicode/language-identifiers.html
LANGUAGE_CODE = 'en-EN'
LANGUAGE_CODE = 'ru-RU'

SITE_ID = 1

# If you set this to False, Django will make some optimizations so as not
# to load the internationalization machinery.
USE_I18N = True

# If you set this to False, Django will not format dates, numbers and
# calendars according to the current locale
USE_L10N = True  

# Absolute filesystem path to the directory that will hold user-uploaded files.
# Example: "/home/media/media.lawrence.com/media/"
# URL that handles the media served from MEDIA_ROOT. Make sure to use a
# trailing slash.
# Examples: "http://media.lawrence.com/media/", "http://example.com/media/"
MEDIA_URL = '/media/'
MEDIA_ROOT = (os.path.join(_PATH, 'media'),)

# URL prefix for static files.
# Example: "http://media.lawrence.com/static/"
STATIC_URL = '/static/'
# URL prefix for admin static files -- CSS, JavaScript and images.
# Make sure to use a trailing slash.
# Examples: "http://foo.com/static/admin/", "/static/admin/".
#ADMIN_MEDIA_PREFIX = '/static/admin/'

# Additional locations of static files
STATICFILES_DIRS = (
    # Put strings here, like "/home/html/static" or "C:/www/django/static".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
)
# Absolute path to the directory static files should be collected to.
# Don't put anything in this directory yourself; store your static files
# in apps' "static/" subdirectories and in STATICFILES_DIRS.
# Example: "/home/media/media.lawrence.com/static/"

STATIC_ROOT = os.path.join(_PATH, 'static')
# List of finder classes that know how to find static files in
# various locations.
#STATICFILES_FINDERS = (
#    'django.contrib.staticfiles.finders.FileSystemFinder',
#    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
#    'django.contrib.staticfiles.finders.DefaultStorageFinder',
#)

# Make this unique, and don't share it with anybody.
SECRET_KEY = 'yourw3afpasswordphrase'

# List of callables that know how to import templates from various sources.
TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.Loader',
    'django.template.loaders.app_directories.Loader',
)

ROOT_URLCONF = 'w3af_webui.urls'

# path for w3af reports and profiles in your system
HTML_REPORT_UPLOAD = '/var/local/w3af-webui'
TEMPLATE_DIRS = (
    # Put strings here, like "/home/html/django_templates" or "C:/www/django/templates".
    # Always use forward slashes, even on Windows.
    # Don't forget to use absolute paths, not relative paths.
    os.path.join(_PATH, 'templates'),
    HTML_REPORT_UPLOAD,
    '/usr/share/pyshared/django/contrib/admin/static/admin',
)

CARROT_BACKEND = "django"
COVERAGE_REPORT_HTML_OUTPUT_DIR = os.path.join(_PATH, 'cover')
# TIME DELTA TO FIND SCAN
FSCAN_TDELTA = {
    'max': timedelta(seconds=62),
    'min': timedelta(seconds=1),
}
# DOMAIN
APP_DOMAIN = 'w3af.sourceforge.net'

# PRESET USER GROUPS PREFIX
PUG_PREFIX = 'w3af_webui'

# Week day name
WEEK_DAY_NAME = (_('Monday'), _('Tuesday'), _('Wednesday'), _('Thursday'),
                 _('Friday'), _('Saturday'), _('Sunday'))
# Scan statuses
TASK_STATUS_KEYS = ('free', 'lock',)
TASK_STATUS = dict(zip(TASK_STATUS_KEYS, range(1, len(TASK_STATUS_KEYS) + 1)))

#Report statuses
SCAN_STATUS_KEYS = ('in_process', 'done', 'fail')
SCAN_STATUS = dict(zip(SCAN_STATUS_KEYS, range(1, len(SCAN_STATUS_KEYS) + 1)))

# Scan repet types
SCAN_REPEAT_KEYS = (_('never'), _('daily'), _('weekly'), _('monthly'),)
SCAN_REPEAT = dict(zip(SCAN_REPEAT_KEYS, range(1, len(SCAN_REPEAT_KEYS) + 1)))

SCAN_DEFAULT_PROFILE = "\n"

# jcelery
BROKER_HOST     = "localhost"
BROKER_PORT     = 3306
BROKER_VHOST    = "/"
BROKER_USER     = "guest"
BROKER_PASSWORD = "guest"
CELERYD_CONCURRENCY = 10
CELERYD_LOG_LEVEL   = "INFO"

AUTH_PROFILE_MODULE = 'w3af_webui.Profile'

EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_PORT = 25 # port for SMTP
#EMAIL_HOST = 'your-relay.domain.net' # SMTP relay for e-mail notification

APP_URL = 'http://your_domain.net'

W3AF_RUN = 'w3af_console'
W3AF_OUTPUT_PLUGIN = 'output.htmlFile' # default output plugin for all scans

TARGET_COMMENT_LABEL = _('Comment')
# set permissions for users
USER_ROLES = {
            'admin' : {
                'email_prefix' : 'admin',
                'groups' : ['scan_manage',
                            'scanprofile_manage',
                            'target_manage',
                            'auth_manage',
                            'scantask_manage',
                            ],
                'description' : 'admin',
            },
            'manager' : {
                'email_prefix' : 'manager',
                'groups' : ['scan_manage','scantask_manage',],
                'description' : 'manager (can start scans)',
            },
            'advanced_manager' : {
                'email_prefix' : 'advanced_manager',
                'groups' : ['scan_manage',
                            'scanprofile_manage',
                            'scantask_manage',
                           ],
                'description' : 'advanced manager (can start scans'
                                ' and configure scan profiles)',
            },
            'engineer' : {
                'email_prefix' : 'engineer',
                'groups' : ['scan_manage',
                            'scanprofile_manage',
                            'target_manage',
                            'scantask_manage',
                           ],
                'description' : 'engineer (can add targets, configure'
                                ' scan profiles and start scans)',
            },
        } 

#------import local settings
AUTH_MIDDLEWARE = ()
TEMPLATE_CONTEXT_PROCESSORS = ()
INSTALLED_APPS = ()
try:
     from local_settings import *
except Exception, e:
    print 'Can not find local settings: %s' % e

try:
     from extra_settings import * # optional settings with your own auth
except Exception, e:
    print 'Can not find extra settings: %s' % e
    AUTH_MIDDLEWARE = (
        'django.contrib.auth.middleware.AuthenticationMiddleware',
    )

MIDDLEWARE_CLASSES = ((
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',) + 
    AUTH_MIDDLEWARE + 
    ('django.middleware.doc.XViewMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'w3af_webui.middleware.I18NMiddleware',
    ))

TEMPLATE_CONTEXT_PROCESSORS += (
    'django.core.context_processors.debug',
    'django.core.context_processors.i18n',
    'django.core.context_processors.media',
    'django.contrib.auth.context_processors.auth',
    'django.core.context_processors.static', 
    'django.core.context_processors.request',
    'django.contrib.messages.context_processors.messages',
)

INSTALLED_APPS += (
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.sites',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'django.contrib.admin',
    #'django_any',
    
    'djcelery',
    'ghettoq',
    'djkombu',
    
    'w3af_webui',
    'south',
    'django_extensions',
    #'django_coverage',
)

import djcelery
djcelery.setup_loader()
