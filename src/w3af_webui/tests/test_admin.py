#-*- coding: utf-8 -*-
from mock import patch
from datetime import time

from django.test import TestCase
from django.utils import unittest
from django_any.models import any_model
from django.conf import settings
from django.contrib.auth.models import User
from django.core.management import call_command
from django.test.client import Client

from w3af_webui.admin import generate_cron_daily
from w3af_webui.admin import generate_cron_monthly
from w3af_webui.admin import generate_cron_weekly
from w3af_webui.management import init_user_group
from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import Scan
from w3af_webui.models import Profile


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


class TestGenerateCronFunction(TestCase):
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


