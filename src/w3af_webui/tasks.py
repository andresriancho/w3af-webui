# -*- coding: utf-8 -*-
from logging import getLogger

from django.core.management import call_command

from celery.schedules import crontab
from celery.task import task
from celery.task import periodic_task

logger = getLogger(__name__)

@periodic_task(run_every=crontab(hour="*", minute="*", day_of_week="*"))
def find_scans(*args, **kwargs):
    '''Search active scans'''
    call_command('find_scans', *args)
    return 1

@task()
def scan_start(*args, **kwargs):
    '''Start scan job by report id'''
    try:
        call_command('w3af_run', *args)
    except Exception, exc:
        logger.error("task.py scan_start exception %s" % exc)
    return 2
