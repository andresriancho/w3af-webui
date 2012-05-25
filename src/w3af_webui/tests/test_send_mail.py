#-*- coding: utf-8 -*-
from mock import patch

from django.test import TestCase
from django_any.models import any_model
from django.conf import settings
from django.contrib.auth.models import User
from django.core import mail

from w3af_webui.notification import send_mail
from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import Scan
from w3af_webui.models import Profile

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

    def test_notify(self):
        # Empty the test outbox
        mail.outbox = []
        result = send_mail.notify(self.user,
                                  self.scan.scan_task.target,
                                  self.scan.id)
        self.assertEqual(len(mail.outbox), 1)
        self.assertTrue(result)

    def test_notify_about_fail(self):
        # Empty the test outbox
        mail.outbox = []
        result = send_mail.notify_about_fail(self.user,
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
