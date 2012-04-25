#-*- coding: utf-8 -*-
from mock import patch

from django.conf import settings
from django.test import TestCase
from django_any.models import any_model
from django.utils import unittest
from django.contrib.auth.models import User
from django.test.client import Client
from django.test.client import RequestFactory
from django.test.utils import override_settings

from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import Scan
from w3af_webui.models import Vulnerability
from w3af_webui.views import get_select_code
from w3af_webui.views import get_extra_button
from w3af_webui.views import show_report
from w3af_webui.views import show_report_txt
from w3af_webui.views import user_settings

class TestGetCode(TestCase):
    @override_settings(VULN_POST_MODULE={'label': 'test_btn',
                                         'module': 'test' })
    def test_get_extra_button(self):
        btn_code = get_extra_button()
        self.assertIn('input', btn_code)
        self.assertIn('test_btn', btn_code)

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


class TestView(unittest.TestCase):
    def setUp(self):
        User.objects.all().delete()
        # Every test needs a client.
        self.user = User.objects.create_user('new_unittest1',
                                             'test@example.com',
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
        self.scan = Scan.objects.create(scan_task=self.scan_task,
                                        user=self.user,)
        self.vuln = any_model(Vulnerability,
                        scan=self.scan,
                        )
        # Every test needs access to the request factory.
        self.factory = RequestFactory()

    def test_user_settings_get(self):
        # Issue a GET request.
        request = self.factory.get('/user_settings/',)
        request.user = self.user
        request.yauser = self.user
        response = user_settings(request)
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)
        return
        #self.assertIn(response.status_code,[200, 302])
        response = self.client.post('/user_settings/',
                                    {'list_per_page': '90',
                                    'iface_lang': 'RU',
                                    'notification': '0', })
        self.assertIn('selected',
                      response.context.__getitem__('form').notification)

    def test_show_report_get(self):
        request = self.factory.get('/show_report/%s/' % self.scan.id)
        request.user = self.user
        request.yauser = self.user
        request.follow = True
        response = show_report(request, self.scan.id)
        self.assertEqual(response.status_code, 200)

    @patch('django.contrib.messages.success')
    @patch('django.contrib.messages.error')
    @patch('w3af_webui.views.get_vulnerability_module')
    def test_show_report_post(self, mock_import, mock_err_msg, mock_succ_msg):
        request = self.factory.post(
                '/show_report/%s/' % self.scan.id,
                 {'vuln_id': self.vuln.id,}
                 )
        request.user = self.user
        request.yauser = self.user
        mock_import.return_value = ''
        response = show_report(request, self.scan.id)
        self.assertEqual(response.status_code, 403) # CSRF!
        self.assertFalse(mock_err_msg.called)
        self.assertFalse(mock_succ_msg.called)

    def test_show_report_txt(self):
        # Issue a GET request.
        request = self.factory.get('/show_report_txt/%s/' % self.scan.id)
        request.user = self.user
        request.yauser = self.user
        response = show_report_txt(request, self.scan.id)
        # Check that the response is 200 OK.
        self.assertEqual(response.status_code, 200)

    @patch('w3af_webui.tasks.scan_start.delay')
    @patch('w3af_webui.models.ScanTask.create_scan')
    def test_run_now_200(self, mock_create_scan, mock_delay):
        self.assertFalse(mock_create_scan.called)
        self.assertFalse(mock_delay.called)
        response = self.client.get('/run_now/', {'id': self.scan.id},
                                   follow=True,
                                   )
        self.assertEqual(response.status_code, 200)
        self.assertTrue(mock_create_scan.called, 'create_scan does not call')
        self.assertTrue(mock_delay.called, 'delay function does not call')

    @patch('w3af_webui.tasks.scan_start.delay')
    @patch('w3af_webui.models.ScanTask.create_scan')
    def test_run_now_404(self, mock_create_scan, mock_delay):
        # bad request (404)
        response = self.client.get('run_now/')
        self.assertFalse(mock_create_scan.called)
        self.assertFalse(mock_delay.called)
        self.assertEqual(response.status_code, 404, 'Must return 404')

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


