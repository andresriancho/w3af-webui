# -*- coding: utf-8 -*-
from django.conf import settings
from django.core.management.base import BaseCommand
from w3af_webui.models import Scan

class Command(BaseCommand):
    help = (u'stop all running task')
    def handle(self, *args, **options):
        active_scans = Scan.objects.all().filter(
                status=settings.SCAN_STATUS['in_process'])
        for scan in active_scans:
            message = ('Scan was stopped by command stop_all_task.'
                       ' Maybe somebody restarted celery')
            scan.unlock_task(message)
