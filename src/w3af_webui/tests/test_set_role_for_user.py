#-*- coding: utf-8 -*-
from mock import patch

from django.test import TestCase
from django.contrib.auth.models import User
from django.contrib.auth.models import Group

from w3af_webui.management import init_user_group
from w3af_webui.management import create_superuser
from w3af_webui.management import create_permission


class TestInitUserGroup(TestCase):
    @patch('w3af_webui.management.create_superuser')
    def test_init_user_group(self, mock_superuser):
        Group.objects.all().delete()
        self.assertEqual(0, Group.objects.count())
        self.assertFalse(mock_superuser.called)
        init_user_group('w3af_webui')
        self.assertTrue(mock_superuser.called)
        self.assertEqual(6, Group.objects.count())

    def test_create_superuser(self):
        self.assertEqual(0, User.objects.count())
        create_superuser()
        self.assertEqual(1, User.objects.count())

    def test_create_permission(self):
        permission = create_permission('test_perm', 'test_desc')
        self.assertNotEqual(None, permission)
        self.assertEqual('test_perm', permission.codename)
        self.assertEqual('test_desc', permission.name)

