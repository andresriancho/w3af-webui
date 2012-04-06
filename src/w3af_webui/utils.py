# -*- coding: utf-8 -*-
from logging import getLogger
from datetime import timedelta
from datetime import datetime

from celery.schedules import crontab
from celery.schedules import schedule
from djcelery.models import PeriodicTask
from djcelery.models import IntervalSchedule
from djcelery.models import CrontabSchedule

logger = getLogger(__name__)
"""
@task()
def scan_create_start(*args, **kwargs):
    '''Start scan job by report id
    args = [scan_task_id, ]
    '''
    print 'scan_ start %s' % args
    try:
        scan_task = ScanTask.objects.get(pk=int(args[0]))
        scan = scan_task.run()
        call_command('w3af_run', scan.id)
    except Exception, exc:
        logger.error("task.py scan_start exception %s" % exc)
"""
def periodic_task_remove(task_name):
    tasks = PeriodicTask.objects.filter(name=task_name)
    if tasks:
        tasks[0].delete()

def get_interval(minutes, hour, day_of_month):
    now = datetime.now()
    print 'now = %s' % now
    time_this_month = datetime(now.year,
                               now.month,
                               day_of_month,
                               hour,
                               minutes,
                               )
    print 'time this month = %s' % time_this_month
    if time_this_month > now:
        delta = time_this_month - now
    else:
        delta = time_this_month - now
    #interval = IntervalSchedule.from_schedule(schedule(timedelta(minutes=delta)))
    interval = IntervalSchedule.from_schedule(schedule(delta))
    interval.save()
    print interval
    return interval

    minutes_now = datetime.now().minute
    if minutes > minutes_now:
        delta = minutes - minutes_now
    else:
        delta = 60 - minutes_now + minutes
    interval = IntervalSchedule.from_schedule(schedule(timedelta(minutes=delta)))
    interval.save()
    return interval

def set_cron_schedule(task, minutes, hour, day_of_week):
    task.task = 'w3af_webui.tasks.scan_create_start'
    cron = CrontabSchedule.from_schedule(crontab(minute=minutes,
                                                 hour=hour,
                                                 day_of_week=day_of_week,
                                                 ))
    cron.save()
    task.crontab = cron
    task.interval = None
    task.save()

def set_interval_schedule(task, minutes, hour, day_of_month):
    print 'minutes = %s' % minutes
    print 'hour = %s' % hour
    print 'day of month = %s' % day_of_month
    task.task = 'w3af_webui.tasks.monthly_task'
    interval = get_interval(int(minutes), int(hour), int(day_of_month))
    task.interval = interval
    task.crontab = None
    task.save()
    print 'task interval = %s' % task.interval

def delay_task_generator(task_id, run_at):
    if run_at is None or run_at < datetime.now():
        print 'No delay task in future'
        return
    task_name = 'delay_%s' % task_id
    task, created = PeriodicTask.objects.get_or_create(
                        name=task_name,
                        args=[int(task_id)],
                        task = 'w3af_webui.tasks.delay_task',
                    )
    delta = run_at - datetime.now()
    interval = IntervalSchedule.from_schedule(schedule(delta))
    interval.save()
    task.interval = interval
    task.enabled = True
    task.save()

def periodic_task_generator(task_id, cron_string):
    task_name = str(task_id)
    task, created = PeriodicTask.objects.get_or_create(name=task_name,
                                                       args=[int(task_id)],
                                                       )
    split_cron = cron_string.split()
    minutes = split_cron[0]
    hour = split_cron[1]
    day_of_month = split_cron[2]
    day_of_week = split_cron[4]
    if day_of_month == '*': # does not set day of month
        set_cron_schedule(task, minutes, hour, day_of_week)
    else:
        set_interval_schedule(task, minutes, hour, day_of_month)
    print 'task interval = %s' % task.interval

