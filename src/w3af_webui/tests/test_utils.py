#-*- coding: utf-8 -*-
from mock import patch
import datetime as dt
from datetime import datetime
from dateutil.relativedelta import relativedelta

from django.test import TestCase
from django_any.models import any_model

from w3af_webui.utils import periodic_task_generator
from w3af_webui.utils import delay_task_generator
from w3af_webui.utils import periodic_task_remove
from w3af_webui.utils import set_cron_schedule
from w3af_webui.utils import get_interval
from w3af_webui.utils import set_interval_schedule
from w3af_webui.models import ScanTask

from djcelery.models import PeriodicTask

class TestTaskGenerator(TestCase):
    def setUp(self):
        PeriodicTask.objects.all().delete()
        self.task, created = PeriodicTask.objects.get_or_create(
                        name='test',
                        task='w3af_webui.tasks.test_task',
                        )
        self.scan_task = any_model(ScanTask,
                           last_updated='0',)

    def test_set_interval_schedule(self):
        now = datetime.now()
        minutes = int(now.minute) + 1
        set_interval_schedule(self.task, minutes, now.hour, now.day)
        self.task = PeriodicTask.objects.get(id=self.task.id)
        self.assertEqual(self.task.interval.period, 'seconds')
        self.assertGreater(self.task.interval.every, 1)
        self.assertLess(self.task.interval.every, 61)
        self.assertEqual(self.task.crontab, None)

    def test_get_interval(self):
        minute_late = datetime.now() + dt.timedelta(minutes=1)
        interval = get_interval(minute_late.minute, minute_late.hour, minute_late.day)
        self.assertEqual(interval.period, 'seconds')
        self.assertGreater(interval.every, 1)
        self.assertLess(interval.every, 61)
        #next_month = (datetime.now() - dt.timedelta(hours=1))
        next_month = datetime.now() - dt.timedelta(hours=1) + relativedelta(months=+1)
        interval = get_interval(next_month.minute, next_month.hour, next_month.day)
        self.assertEqual(interval.period, 'seconds')
        self.assertGreater(interval.every, 2419200) # 28 days


    def test_set_cron_schedule(self):
        set_cron_schedule(self.task, '*', '*', '*')
        self.task = PeriodicTask.objects.get(id=self.task.id)
        self.assertNotEqual(self.task.crontab, None)
        self.assertEqual(self.task.interval, None)

    @patch('w3af_webui.utils.set_interval_schedule')
    @patch('w3af_webui.utils.set_cron_schedule')
    def test_task_generator(self, mock_set_cron, mock_set_interval):
        self.assertFalse(mock_set_cron.called)
        self.assertFalse(mock_set_interval.called)

        PeriodicTask.objects.all().delete()
        init_count = PeriodicTask.objects.count()
        # simple cron task
        periodic_task_generator('222', '35 * * * *')
        self.assertEqual(init_count + 1, PeriodicTask.objects.count())
        self.assertTrue(mock_set_cron.called)
        self.assertFalse(mock_set_interval.called)
        # monthly task - special case
        periodic_task_generator('222', '35 * 5 * *')
        self.assertEqual(init_count + 1, PeriodicTask.objects.count())
        self.assertTrue(mock_set_interval.called)

    def test_delay_task_generator(self):
        run_at = datetime.now() + dt.timedelta(days=1)
        delay_task = delay_task_generator(self.scan_task.id, run_at)
        delay_task, created = PeriodicTask.objects.get_or_create(
                        name='delay_%s' % self.scan_task.id,
                    )
        self.assertFalse(created)
        self.assertTrue(delay_task.enabled)
        self.assertNotEqual(delay_task.interval, None)


class TestTaskRemove(TestCase):
    def test_task_remove(self):
        task, created = PeriodicTask.objects.get_or_create(
                        name='test_task',
                        task="w3af_webui.tasks.test_task",
                        )
        task.save()
        init_count = PeriodicTask.objects.count()
        periodic_task_remove('test_task') # remove exist task
        self.assertEqual(init_count - 1, PeriodicTask.objects.count())

        periodic_task_remove('not_exist') # remove not exist task
        self.assertEqual(init_count - 1, PeriodicTask.objects.count())


