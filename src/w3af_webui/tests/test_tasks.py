#-*- coding: utf-8 -*-
from mock import patch
from unittest import skip
from django.test import TestCase
from django_any.models import any_model
from django.conf import settings

from w3af_webui.tasks import monthly_task
from w3af_webui.tasks import delay_task
from w3af_webui.tasks import scan_create_start
from w3af_webui.models import ScanTask

from djcelery.models import PeriodicTask

class TestCreateStartTask(TestCase):
    def  setUp(self):
        self.scan_task = any_model(ScanTask,
                                   status=settings.TASK_STATUS['free'],
                                   last_updated='0',)
        self.scan_task.save()


    def test_fail_scan_create_start(self):
        self.assertRaises(ScanTask.DoesNotExist,
                          scan_create_start,
                          -1,
                          )


@skip('PeriodicTask in this test is initialized incorrectly.')
class TestDelayTask(TestCase):
    def  setUp(self):
        self.task, created = PeriodicTask.objects.get_or_create(
                        name='delay_22',
                        task='w3af_webui.tasks.delay_task',
                        interval=None,
                        args=[22,],
                        )
        self.task.save()

    @patch('w3af_webui.tasks.scan_create_start')
    def test_delay_task(self, mock_create_start):
        self.assertFalse(mock_create_start.called)
        delay_task(self.task.args[0])
        self.assertEqual(PeriodicTask.objects.get(id=self.task.id).enabled, False)
        self.assertEqual(PeriodicTask.objects.get(id=self.task.id).interval, None)
        self.assertTrue(mock_create_start.called)


@skip('PeriodicTask in this test is initialized incorrectly.')
class TestMonthlyTask(TestCase):
    def setUp(self):
        self.task, created = PeriodicTask.objects.get_or_create(
                        name='22',
                        task='w3af_webui.tasks.monthly_task',
                        args=[22],
                        )
        self.task.save()

    @patch('w3af_webui.tasks.scan_create_start')
    def test_monthly_task(self, mock_create_start):
        self.assertFalse(mock_create_start.called)
        monthly_task(*self.task.args)
        self.assertNotEqual(PeriodicTask.objects.get(id=self.task.id).interval, None)
        self.assertTrue(mock_create_start.called)


