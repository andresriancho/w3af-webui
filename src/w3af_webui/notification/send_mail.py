#!/usr/bin/env python
#-*- coding: utf-8 -*-
from django.core.mail import send_mail
from django.conf import settings

from logging import getLogger

logger = getLogger(__name__)
def notify(user, target, scan_id):
    report_link = '%s/show_report/%s/' % (
        settings.APP_URL,
        scan_id, )
    message = 'Scan %s was finished.  %s' % (target, report_link)
    subj = 'Scan %s was finished' % target
    try:
        send_mail(subj, message, user.email, [user.email], fail_silently=False)
    except Exception, e:
        logger.error('Can not send mail: %s' % e)
        return False
    return True
