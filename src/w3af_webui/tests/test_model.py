#-*- coding: utf-8 -*-
from mock import patch
from datetime import datetime
from subprocess import Popen
from subprocess import PIPE

from django.test import TestCase
from django_any.models import any_model
from django.conf import settings
from django.contrib.auth.models import User

from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.models import kill_process

class TestScanProfile(TestCase):
    def test_add(self):
        self.assertEqual(0, ScanProfile.objects.count())
        ScanProfile.objects.create()
        self.assertEqual(1, ScanProfile.objects.count())


class TestTarget(TestCase):
    def test_add(self):
        self.assertEqual(0, Target.objects.count())
        Target.objects.create()
        self.assertEqual(1, Target.objects.count())


class TestScanModel(TestCase):
    def setUp(self):
        self.target = any_model(Target)
        self.scan_task = ScanTask.objects.create(target=self.target)

    def test_add(self):
        self.assertEqual(0, Scan.objects.count())
        scan_first = Scan.objects.create(scan_task=self.scan_task)
        Scan.objects.create(scan_task=self.scan_task)
        self.assertEqual(2, Scan.objects.count())
        self.assertEqual(self.scan_task, scan_first.scan_task)
        self.assertEqual(settings.SCAN_STATUS['in_process'], scan_first.status)

    def test_set_task_status_free(self):
        scan_task = any_model(ScanTask, status=settings.TASK_STATUS['lock'],)
        scan = any_model(Scan, scan_task=scan_task,
                        status=settings.SCAN_STATUS['in_process'],
                        start=datetime.now(),
                        pid=1)
        self.assertEqual(scan_task.status, settings.TASK_STATUS['lock'])
        scan.set_task_status_free()
        self.assertEqual(scan_task.status, settings.TASK_STATUS['free'])

    @patch('w3af_webui.models.kill_process')
    def test_unlock_task(self, mock_kill_process):
        '''test for scan task delay'''
        scan_task = any_model(ScanTask, status=settings.TASK_STATUS['lock'],)
        scan = any_model(Scan, scan_task=scan_task,
                        status=settings.SCAN_STATUS['in_process'],
                        start=datetime.now(),
                        pid=1)
        message = 'from tests'
        mock_kill_process.return_value = True
        ################################################
        self.assertFalse(mock_kill_process.called)
        self.assertEqual(scan.status, settings.SCAN_STATUS['in_process'])
        self.assertEqual(scan_task.status, settings.TASK_STATUS['lock'])
        # call unlock_task mothod 
        result = scan.unlock_task(message)
        self.assertTrue(mock_kill_process.called)
        self.assertTrue(result)
        self.assertEqual(scan_task.status, settings.TASK_STATUS['free'])
        self.assertEqual(scan.status, settings.SCAN_STATUS['fail'])
        self.assertEqual(scan.result_message, message)
        ################################################
        scan_done = any_model(Scan, scan_task=scan_task,
                              status=settings.SCAN_STATUS['done'],
                              start=datetime.now() )
        self.assertEqual(scan_done.status, settings.SCAN_STATUS['done'],
                         'done status before call')
        result = scan_done.unlock_task(message)
        self.assertFalse(result, 'невозмозно завершить просесс со статусом done')
        self.assertEqual(scan_done.status, settings.SCAN_STATUS['done'],
                         'done status after call')
        ################################################
        scan_fail = any_model(Scan, scan_task=scan_task,
                              status=settings.SCAN_STATUS['fail'],
                              start=datetime.now() )
        self.assertEqual(scan_fail.status, settings.SCAN_STATUS['fail'])
        result = scan_fail.unlock_task(message)
        self.assertFalse(result, 'невозмозно завершить просесс со статусом fail')
        self.assertEqual(scan_fail.status, settings.SCAN_STATUS['fail'])


class TestScanTaskModel(TestCase):
    def setUp(self):
        self.target = any_model(Target)
        self.user = User.objects.create_user('scan_task_user', 'test@example.com',
                                        'scan_task_user')
        self.user.save()

    def test_add(self):
        self.assertEqual(0, ScanTask.objects.count())
        scan_task_first = ScanTask.objects.create(target=self.target)
        scan_task_second = ScanTask.objects.create(target=self.target)
        self.assertEqual(2, ScanTask.objects.count())
        self.assertEqual(self.target, scan_task_first.target)
        self.assertEqual(self.target, scan_task_second.target)

    def test_create_scan(self):
        '''test for scan task delay'''
        scan_task = any_model(ScanTask,
                              status=settings.TASK_STATUS['free'],
                              last_updated='0')
        self.assertEqual(0, Scan.objects.count())
        scan = scan_task.create_scan(self.user)
        self.assertEqual(1, Scan.objects.count())
        self.assertEqual(scan_task.status, settings.TASK_STATUS['lock'])
        self.assertNotEqual(scan_task.last_updated, '0')
        self.assertEqual(scan.scan_task, scan_task)
        self.assertNotEqual(scan.start, '0')


class TestProfileModel(TestCase):
     def test_user_post_save(self):
        self.assertEqual(0, Profile.objects.count())
        new_user = User.objects.create()
        self.assertEqual(1, Profile.objects.count())
        new_user.save()
        self.assertEqual(1, Profile.objects.count())


class TestKillProcFunction(TestCase):
    @patch('os.kill')
    def test_kill_process(self, mock_kill):
        proc = Popen(['python'], stdout=PIPE, stderr=PIPE)
        result = kill_process(proc.pid)
        self.assertEqual(True, result)
        self.assertTrue(mock_kill.called)

        mock_kill.reset_mock()
        result = kill_process('w')
        self.assertEqual(False, result)
        self.assertFalse(mock_kill.called)

        result = kill_process('1')
        self.assertEqual(False, result)
        self.assertFalse(mock_kill.called)


