#-*- coding: utf-8 -*-
from django.core.mail import send_mail
from django.conf import settings

from logging import getLogger

logger = getLogger(__name__)

def send(subj, message, email):
    try:
        send_mail(subj, message, email, [email], fail_silently=False)
    except Exception, e:
        logger.error('Can not send mail: %s' % e)
        return False
    return True

def notify(user, target, scan_id):
    report_link = '%s/show_report/%s/' % (
        settings.APP_URL,
        scan_id, )
    message = 'Scan %s was finished.  %s' % (target, report_link)
    subj = 'Scan %s was finished' % target
    return send(subj, message, user.email)

def notify_about_fail(user, target, scan_id):
    log_link = '%s/show_report_txt/%s/' % (
        settings.APP_URL,
        scan_id, )
    message = ('Scan %s was not finished successfully. Show log file for '
               'more details %s' % (target, log_link))
    subj = 'Scan %s was failed' % target
    return send(subj, message, user.email)
