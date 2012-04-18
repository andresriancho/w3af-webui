#-*- coding: utf-8 -*-
import os
from shutil import rmtree
from datetime import datetime
from datetime import time
from subprocess import Popen
from subprocess import PIPE
from mock import patch
from time import sleep

from django.test import TestCase
from django_any.models import any_model
from django.conf import settings
from django.utils import unittest
from django.test.client import Client
from django.core.management import call_command
from django.contrib.auth.models import User
from django.core import mail
from django.contrib.auth.models import Group

from w3af_webui import models as m
from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import ProfilesTasks
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.views import get_select_code
from w3af_webui.management.commands.w3af_run import fail_scan
from w3af_webui.management.commands.w3af_run import get_profile
from w3af_webui.management.commands.w3af_run import get_report_path
from w3af_webui.management.commands.w3af_run import send_notification
from w3af_webui.management.commands.w3af_run import post_finish
from w3af_webui.management.commands.w3af_run import save_vulnerabilities
from w3af_webui.management import init_user_group
from w3af_webui.management import create_superuser
from w3af_webui.management import create_extra_permission
from w3af_webui.notification import send_mail
from w3af_webui.utils import periodic_task_generator
from w3af_webui.utils import delay_task_generator
from w3af_webui.utils import periodic_task_remove
from w3af_webui.utils import get_interval
from w3af_webui.utils import set_interval_schedule
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


    def delay_task_generator(self):
        run_at = datetime.now()
        run_at.minute += 1
        self.task.enable = False
        self.task.interval = None
        self.task.save()
        delay_task_generator(self.task.id, run_at)
        self.assertEqual(PeriodicTask.objects.get(id=self.task.id).enabled, True)
        self.assertNotEqual(PeriodicTask.objects.get(id=self.task.id).interval, None)


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


class TestTaskGenerator(TestCase):
    def setUp(self):
        self.task, created = PeriodicTask.objects.get_or_create(
                        name='test',
                        task='w3af_webui.tasks.test_task',
                        )
        self.task.save()

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
        now = datetime.now()
        minutes = int(now.minute) + 1
        interval = get_interval(minutes, now.hour, now.day)
        self.assertEqual(interval.period, 'seconds')
        self.assertGreater(interval.every, 1)
        self.assertLess(interval.every, 61)

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


class TestView(unittest.TestCase):
    def setUp(self):
        # Every test needs a client.
        self.user = User.objects.create_user('new_unittest1', 'test@example.com',
                                        'new_test_password')
        self.user.save()
        self.client = Client()
        self.client.login(username='new_unittest1',
                          password='new_test_password')
        self.profile = any_model(ScanProfile)
        self.target = any_model(Target)
        self.scan_task = any_model(ScanTask,
                                   status=settings.TASK_STATUS['free'],
                                   target=self.target,
                                   last_updated='0',)
        self.scan = Scan.objects.create(scan_task=self.scan_task,)

    def tearDown(self):
        self.user.delete()
        self.profile.delete()
        self.target.delete()
        self.scan_task.delete()
        self.scan.delete()

    def _test_user_settings(self):
        # Issue a GET request.
        response = self.client.get('/user_settings/',
                                   follow=True)
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)
        #self.assertIn(response.status_code,[200, 302])
        response = self.client.post('/user_settings/',
                                    {'list_per_page': '90',
                                    'iface_lang': 'RU',
                                    'notification': '0', })
        self.assertIn('selected',
                      response.context.__getitem__('form').notification)

    def test_show_report(self):
        # Issue a GET request.
        print self.scan.id
        response = self.client.get('/show_report/%s/' % self.scan.id,
                                   follow=True)
        # Check that the response is 404 OK - report file does not exist
        self.assertEqual(response.status_code, 404)

    def test_fail_show_report(self):
        # Issue a GET request without id in queryset.
        response = self.client.get('/show_report/xxx')
        # Check that redirect done.
        self.assertEqual(response.status_code, 404)

    def _test_show_report_txt(self):
        # Issue a GET request.
        response = self.client.get('/show_report_txt/%s/' % self.scan.id)
        # Check that the response is 200 OK.
        #self.assertIn(response.status_code,[200, 302])
        self.assertEqual(response.status_code, 200)
        # Issue a GET request without id in queryset.
        response = self.client.get('/show_report_txt/xxx')
        # Check that redirect done.
        self.assertEqual(response.status_code, 404)

    @patch('w3af_webui.tasks.scan_start.delay')
    @patch('w3af_webui.models.ScanTask.create_scan')
    def test_run_now(self, mock_create_scan, mock_delay):
        self.assertFalse(mock_create_scan.called)
        self.assertFalse(mock_delay.called)
        response = self.client.get('/run_now/', {'id': self.scan.id},
                                   follow=True,
                                   )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(mock_create_scan.called)
        self.assertTrue(mock_delay.called)
        # bad request (404)
        mock_create_scan.reset_mock()
        mock_delay.reset_mock()
        response = self.client.get('run_now/')
        self.assertFalse(mock_create_scan.called)
        self.assertFalse(mock_delay.called)
        self.assertEqual(response.status_code, 404)

    @patch('w3af_webui.models.ScanTask.create_scan')
    @patch('w3af_webui.models.Scan.unlock_task')
    @patch('w3af_webui.tasks.scan_start.delay')
    def test_run_now_exc(self, mock_delay, mock_unlock, mock_create_scan):
        exc = Exception('Boom!')
        mock_delay.side_effect = exc
        mock_create_scan.return_value = self.scan
        self.client.get('/run_now/',
                       {'id': self.scan.id},
                       follow=True,
                       )
        self.assertRaises(Exception,
                          self.client.get('/run_now/',
                                         {'id': self.scan.id},
                                         follow=True,
                                        )
                          )
        self.assertTrue(mock_unlock.called)


    def test_check_url(self):
        # Issue a GET request.
        response = self.client.get('/check_url/',
                                  {'url':
                                   'http://w3af.sourceforge.net/'})
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)
        response = self.client.get('/check_url/',
                                  {'url': 'test.test'})
        self.assertEqual(response.status_code, 404)

    def test_stop_scan(self):
        # Issue a GET request.
        #self.client.META['HTTP_REFERER'] = '/w3af_webui/scan/'
        #response = self.client.get('/stop_scan/', { 'id': self.scan.id})
        # Check that the response is 200 OK.
        #self.assertEqual(response.status_code, 302)
        # Issue a GET request without id in queryset.
        response = self.client.get('/stop_scan/')
        # Check that redirect done.
        self.assertEqual(response.status_code, 404)


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


class TestGetSelectCode(TestCase):
    def test_get_select_code(self):
        list_per_page_values = (
            ('10', '10'),
            ('30', '30'),
            ('50', '50'),
            ('70', '70'),
            ('90', '90'),
            ('100', '100'),
            )
        select_code = get_select_code('50', list_per_page_values, 'list_per_page')
        self.assertIn('select', select_code)
        self.assertIn('</select>', select_code)
        self.assertIn('</option>', select_code)
        self.assertIn('selected', select_code)
        self.assertIn('list_per_page', select_code)


class TestW3afRun(TestCase):
    def setUp(self):
        Scan.objects.all().delete()
        user = User.objects.create_user('svetleo', 'user@example.com', '!')
        user.save()
        self.target = any_model(Target)
        self.scan_task = any_model(ScanTask,
                                   user=user,
                                   status=settings.TASK_STATUS['free'],
                                   target=self.target,
                                   last_updated='0',
                                   cron="",)
        self.scan = Scan.objects.create(
                                scan_task=self.scan_task,
                                data='test',
                                status=settings.SCAN_STATUS['in_process'])

    @patch('w3af_webui.notification.send_mail.notify')
    def test_send_notification(self, mock_send_mail):
        # notification = None
        none_index = max(index for index, value in enumerate(settings.NOTIFY_MODULES)
                         if value['id'] == 'None')
        user = self.scan_task.user
        user.get_profile().notification = none_index # None
        user.save()
        result = send_notification(self.scan)
        self.assertTrue(result)
        self.assertFalse(mock_send_mail.called)
        # fake notification
        user.get_profile().notification = 10000 # fake 
        user.save()
        result = send_notification(self.scan)
        self.assertFalse(result)
        self.assertFalse(mock_send_mail.called)
        # notification = Mail
        mail_index = max(index for index, value in enumerate(settings.NOTIFY_MODULES)
                         if value['id'] == 'Mail')
        user.get_profile().notification = mail_index # Mail
        user.save()
        result = send_notification(self.scan)
        self.assertTrue(result)
        self.assertTrue(mock_send_mail.called)

    def test_get_profile(self):
        scan_profile = any_model(ScanProfile)
        any_model(ProfilesTasks,
                  scan_task=self.scan_task,
                  scan_profile=scan_profile)
        profile_name = get_profile(self.scan_task, '/var/tmp', 'test.html')
        #check that this file exist
        self.assertTrue(os.access(profile_name, os.F_OK))

    def test_get_report_path(self):
        report_path = get_report_path()
        self.assertTrue(os.access(report_path, os.F_OK))

    @patch('w3af_webui.models.Scan.set_task_status_free')
    def test_fail_scan(self, mock_status_free):
        scan = Scan.objects.create(scan_task=self.scan_task, data='test',
                                        status=settings.SCAN_STATUS['in_process'])
        self.assertEqual(scan.status, settings.SCAN_STATUS['in_process'])
        self.assertFalse(mock_status_free.called)
        old_result_message = scan.result_message
        new_result_message = 'test msg'
        fail_scan(scan.id, new_result_message)
        scan = Scan.objects.get(pk=int(scan.id))
        #Assert after call
        self.assertTrue(mock_status_free.called)
        self.assertEqual(scan.status, settings.SCAN_STATUS['fail'])
        self.assertEqual(scan.result_message,
                         old_result_message + new_result_message )

    def test_scan_does_not_exist(self):
        #scan does not exist
        self.assertRaises(Scan.DoesNotExist, call_command,
                          'w3af_run', -1)

    @patch('w3af_webui.management.commands.w3af_run.get_report_path')
    @patch('w3af_webui.management.commands.w3af_run.fail_scan')
    def test_w3af_run_exceptions_raises(self, mock_fail_scan, mock_get_report):
        exc = Exception('Boom!')
        mock_get_report.side_effect = exc
        self.assertRaises(Exception, call_command,
                          'w3af_run', self.scan.id)
        self.scan = Scan.objects.get(pk=int(self.scan.id))
        #self.assertEqual(self.scan.status, settings.SCAN_STATUS['fail'])
        self.assertTrue(mock_fail_scan.called)

    @patch('w3af_webui.management.commands.w3af_run.wait_process_finish')
    @patch('w3af_webui.management.commands.w3af_run.post_finish')
    @patch('w3af_webui.management.commands.w3af_run.send_notification')
    @patch('w3af_webui.management.commands.w3af_run.get_profile')
    @patch('w3af_webui.management.commands.w3af_run.get_report_path')
    def test_w3af_run(self, mock_report_path, mock_get_profile,
                      mock_notify, mock_post_finish, mock_wait_process):
        test_report_path = 'test_report/'
        try:
            os.mkdir(test_report_path)
        except Exception, e:
            print e
        mock_report_path.return_value = test_report_path
        mock_get_profile.return_value = 'test'
        # process terminated with error
        mock_wait_process.return_value = 1 # return error
        call_command('w3af_run', self.scan.id)
        self.assertTrue(mock_wait_process.called)
        self.assertTrue(mock_post_finish.called)
        # process terminated without error
        mock_wait_process.return_value = 0 # return error
        mock_post_finish.reset_mock()
        mock_wait_process.reset_mock()
        call_command('w3af_run', self.scan.id)
        self.assertTrue(mock_wait_process.called)
        self.assertTrue(mock_post_finish.called)
        self.assertTrue(mock_report_path.called)
        self.assertTrue(mock_get_profile.called)
        rmtree(test_report_path)

    @patch('w3af_webui.management.commands.w3af_run.fail_scan')
    def test_post_finish(self, mock_fail_scan):
        # bad returncode
        self.assertFalse(mock_fail_scan.called)
        post_finish(self.scan, -9)
        self.assertTrue(mock_fail_scan.called)
        # returncode ok, but task was stoped by user 
        self.scan.status = settings.SCAN_STATUS['fail']
        self.scan.save()
        mock_fail_scan.reset_mock()
        post_finish(self.scan, 0)
        self.assertFalse(mock_fail_scan.called)
        self.assertEqual(Scan.objects.get(pk=int(self.scan.id)).status,
                         settings.SCAN_STATUS['fail'])
        # ok returncode and status
        mock_fail_scan.reset_mock()
        self.scan.status = settings.SCAN_STATUS['in_process']
        self.scan.save()
        post_finish(self.scan, 0)
        self.assertFalse(mock_fail_scan.called)
        self.assertEqual(Scan.objects.get(pk=int(self.scan.id)).status,
                         settings.SCAN_STATUS['done'])

    def test_save_vulner(self):
        save_vulnerabilities(self.scan, '/home/svetleo/tmp/w3af.xml')

    def tearDown(self):
        self.scan.delete()
        self.scan_task.delete()
        self.target.delete()
        Scan.objects.all().delete()


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
