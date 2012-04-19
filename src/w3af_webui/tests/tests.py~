#-*- coding: utf-8 -*-
from datetime import datetime
from datetime import time
from subprocess import Popen
from subprocess import PIPE
from mock import patch

from django.test import TestCase
from django_any.models import any_model
from django.conf import settings
from django.utils import unittest
from django.test.client import Client
from django.core.management import call_command
from django.contrib.auth.models import User
from django.core import mail
from django.contrib.auth.models import Group

from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.management import init_user_group
from w3af_webui.management import create_superuser
from w3af_webui.management import create_extra_permission
from w3af_webui.notification import send_mail
from w3af_webui.tasks import monthly_task
from w3af_webui.tasks import delay_task
from w3af_webui.tasks import scan_create_start
from w3af_webui.models import kill_process
from w3af_webui.admin import generate_cron_daily
from w3af_webui.admin import generate_cron_monthly
from w3af_webui.admin import generate_cron_weekly

from djcelery.models import PeriodicTask

class TestCreateStartTask(TestCase):
    def  setUp(self):
        self.scan_task = any_model(ScanTask,
                                   status=settings.TASK_STATUS['free'],
                                   last_updated='0',)
        self.scan_task.save()

    @patch('django.core.management.call_command')
    def test_fail_scan_create_start(self, mock_call_command):
        self.assertRaises(ScanTask.DoesNotExist,
                          scan_create_start,
                          -1,
                          )


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


class TestInitUserGroup(TestCase):
    @patch('w3af_webui.management.create_superuser')
    def test_init_user_group(self, mock_superuser):
        Group.objects.all().delete()
        self.assertEqual(0, Group.objects.count())
        self.assertFalse(mock_superuser.called)
        init_user_group('w3af_webui')
        self.assertTrue(mock_superuser.called)
        self.assertEqual(5, Group.objects.count())

    def test_create_superuser(self):
        self.assertEqual(0, User.objects.count())
        create_superuser()
        self.assertEqual(1, User.objects.count())

    def test_create_permission(self):
        #self.assertEqual(0, User.objects.count())
        create_extra_permission()
        #self.assertEqual(1, User.objects.count())


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


class TestCommonFunction(TestCase):
    def test_generate_cron_daily(self):
        cron = generate_cron_daily(day=-9090, weekday=-1,
                                     hour_min=time(12, 30),)
        self.assertEqual('30 12 * * *', cron)

    def test_generate_cron_weekly(self):
        cron = generate_cron_weekly(day=-9090, weekday=1,
                                      hour_min=time(12, 30),)
        self.assertEqual('30 12 * * 1', cron)

    def test_generate_cron_monthly(self):
        cron = generate_cron_monthly(day=21, weekday=1,
                                       hour_min=time(12, 30),)
        self.assertEqual('30 12 21 * *', cron)

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


class TestModelAdmin(unittest.TestCase):
    def setUp(self):
        # Every test needs a client.
        User.objects.all().delete()
        self.user_smb = User.objects.create_user('somebody__else', 'smb@example.com',
                                                 'somebody__else')
        self.user_smb.is_staff = True
        self.user_smb.save()
        self.user = User.objects.create_user('new_unittest', 'test@example.com',
                                             'new_test_password')
        init_user_group('w3af_webui')
        call_command('set_role_for_user',
                     'new_unittest')
        self.user.is_staff = True
        self.user.is_superuser = True
        self.user.save()
        self.client = Client()
        self.client.login(username=self.user.username,
                          password='new_test_password')
        self.profile = any_model(ScanProfile, user=self.user)
        self.target = any_model(Target, user=self.user)
        self.not_mine_target = any_model(Target, user=self.user_smb)
        self.scan_task = any_model(ScanTask,
                                   user=self.user,
                                   status=settings.TASK_STATUS['free'],
                                   target=self.target,
                                   last_updated='0',
                                   )
        self.scan = Scan.objects.create(scan_task=self.scan_task,
                                        data='test',
                                        )
    def tearDown(self):
        self.user.delete()
        self.user_smb.delete()
        self.profile.delete()
        Target.objects.all().delete()
        self.scan_task.delete()
        self.scan.delete()

    def test_scan_list(self):
        # Issue a GET request.
        response = self.client.get('/w3af_webui/scan/')
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)

    def test_scantask_list(self):
        # ScanTask: Issue a GET request.
        response = self.client.get('/w3af_webui/scantask/')
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)

    def test_edit_scantask(self):
        # Issue a GET request.
        response = self.client.get(
            '/w3af_webui/scantask/%s/' % self.scan_task.id,
            follow=True,
            )
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)

    def test_target_list(self):
        # Target: Issue a GET request.
        response = self.client.get('/w3af_webui/target/')
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)

    def test_edit_target(self):
        # My Target: Issue a GET request.
        response = self.client.get(
            '/w3af_webui/target/%s/' % self.target.id,
            follow=True,
            )
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)
        return

    def test_scanprofile_list(self):
        # Target: Issue a GET request.
        response = self.client.get('/w3af_webui/scanprofile/')
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)

    def test_edit_scanprofile(self):
        # Target: Issue a GET request.
        response = self.client.get(
            '/w3af_webui/scanprofile/%s/' % self.profile.id,
            follow=True,
            )
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)


"""
class TestFindScans(TestCase):
    def setUp(self):
        Scan.objects.all().delete()
        self.target = any_model(Target)
        self.scan_task = any_model(ScanTask,
                                   status=settings.TASK_STATUS['free'],
                                   target=self.target,
                                   last_updated='0',
                                   repeat_each = 1 # never
                                   )

    @patch('w3af_webui.models.ScanTask.run')
    def test_find_scans_command(self, mock_run):
        self.scan_task.start = datetime.now()
        self.scan_task.save()
        sleep(1)
        call_command('find_scans')
        self.assertTrue(mock_run.called)
        mock_run.resete_mock()
        self.scan_task.repeat_at = time(datetime.now().hour,
                                        datetime.now().minute)
        self.scan_task.repeat_each = 2 # daily
        self.scan_task.save()
        call_command('find_scans')
        self.assertTrue(mock_run.called)
"""

class TestSendMail(TestCase):
    def setUp(self):
        # Every test needs a client.
        self.user = User.objects.create_user('new_unittest',
                                             'user@some-host.ru',
                                             'new_test_password')
        self.user.save()
        self.target = any_model(Target, user=self.user)
        self.scan_task = any_model(ScanTask,
                                   user=self.user,
                                   status=settings.TASK_STATUS['free'],
                                   target=self.target,
                                   last_updated='0',)
        self.scan = any_model(Scan, scan_task=self.scan_task, data='test')

    def tearDown(self):
        self.user.delete()
        self.target.delete()
        self.scan_task.delete()
        self.scan.delete()

    def test_send_mail_notify(self):
        # Empty the test outbox
        mail.outbox = []
        result = send_mail.notify(self.user,
                                  self.scan.scan_task.target,
                                  self.scan.id)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(result)

    @patch('django.core.mail.send_mail')
    def _test_fail_send_mail_notify(self, mock_send_mail):
        mock_send_mail.side_effect =  Exception('Boom!')
        self.assertFalse(mock_send_mail.called)
        result = send_mail.notify(self.user,
                                  self.scan.scan_task.target,
                                  self.scan.id)
        self.assertTrue(mock_send_mail.called)
        self.assertFalse(result)
