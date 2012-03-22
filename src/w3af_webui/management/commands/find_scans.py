# -*- coding: utf-8 -*-
from __future__ import absolute_import

import logging
from cronex import CronExpression
from datetime import datetime

from django.utils.encoding import smart_str
from django.core.management.base import BaseCommand
from django.conf import settings

from w3af_webui.models import ScanTask
from w3af_webui.models import Scan

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    args = '<>'
    help = (u"command for scan task ")

    def handle(self, *args, **options):
        now = datetime.now()
        lock_time = now - settings.FSCAN_TDELTA['max']
        orphan_proc = Scan.objects.filter(
                        status=settings.SCAN_STATUS['in_process'],
                        last_updated__lte=lock_time)
        for obj in orphan_proc:
            obj.unlock_task('find_scans call unlock task')
        for scan_task in ScanTask.objects.filter(
                            status=settings.TASK_STATUS['free']):
            min_time_allowed = now - settings.FSCAN_TDELTA['max']
            # start at fixed time
            if scan_task.start:
                now_delta = now - scan_task.start
                if (now_delta < settings.FSCAN_TDELTA['max'] and
                    now_delta > settings.FSCAN_TDELTA['min']):
                    if not Scan.objects.filter(scan_task=scan_task.id,
                                               finish__gte=min_time_allowed):
                        logger.info('Found waiting time scan: %s' % scan_task.target)
                        scan_task.run()
            # cron-schedule start
            if scan_task.cron:
                job = CronExpression(smart_str(scan_task.cron))
                if job.check_trigger((now.year, now.month, now.day, now.hour,
                                      now.minute)):
                    if not Scan.objects.filter(scan_task=scan_task.id,
                                               finish__gte=min_time_allowed):
                        logger.info('Found waiting cron scan: %s' % scan_task.target)
                        scan_task.run()
