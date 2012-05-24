#-*- coding: utf-8 -*-
from django.core.mail import send_mail
from django.conf import settings
from w3af_webui.notification.send_mail import send
from w3af_webui.models import Scan
from w3af_webui.models import Vulnerability

def notify(user, target, scan_id):
    scan = Scan.objects.get(pk=scan_id)
    vuln = Vulnerability.objects.filter(scan=scan)
    if not vuln:
        return True # nothing 
    report_link = '%s/show_report/%s/' % (
        settings.APP_URL,
        scan_id,
    )
    message = ('Scan %s found %s vulnerability(ies). Show report'
              ' for more details %s' % (target, len(vuln), report_link))
    subj = 'Scan %s found vulnerabilities' % target
    return send(subj, message, user.email)
