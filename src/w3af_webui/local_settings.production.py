#-*- coding: utf-8 -*-
DEBUG = False
TEMPLATE_DEBUG = DEBUG
#---logging---
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
            'level': 'DEBUG',
            'class':'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file':{
            'level': 'DEBUG',
            'class':'logging.FileHandler',
            'formatter': 'verbose',
            'filename': '/var/log/w3af-webui/django.log',
        },
        'mail_admins': {
            'level': 'ERROR',
            'class': 'django.utils.log.AdminEmailHandler'
        }
    },
    'loggers': {
        'django.request': {
            'handlers': ['mail_admins'],
            'level': 'ERROR',
        },
    },
    'root' : {
        'handlers': ['file'],
        'level': 'INFO',
    },
}
CELERYD_LOG_FILE = "/var/log/w3af-webui/celeryd.log"
#MEDIA_ROOT = '/tmp/w3af-webui/'
#MEDIA_ROOT = '/var/local/w3af-webui/'#'tmp/w3af-webui/'
