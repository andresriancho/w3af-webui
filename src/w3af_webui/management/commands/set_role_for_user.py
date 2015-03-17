# -*- coding: utf-8 -*-
from __future__ import absolute_import
from django.contrib.auth.models import Group
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand
from django.conf import settings

from logging import getLogger
from optparse import make_option

logger = getLogger(__name__)
APP = 'w3af_webui'

class Command(BaseCommand):
    args = '<username1 username2 ...>'
    help = (u'Command for group permission creation')
    option_list = BaseCommand.option_list + (
        make_option('--role',
                    dest='role',
                    default='User',
                    help='Setup roles set for user(s)',
                    ),
        )

    def handle(self, *args, **options):
        user = {}
        for username in args:
            user[username] = options['role']

        for username in user.keys():
            new_user = None
            try:
                new_user = User.objects.get(username=username)
            except User.DoesNotExist:
                new_user = User.objects.create_user(
                        username,
                        '',
                        username)
            new_user.is_staff = True
            new_user.groups = []
            if user[username] == 'admin':
                new_user.is_superuser = True
                new_user.save()
                continue
            group_object = Group.objects.get(name=user[username])
            new_user.groups.add(group_object)
            new_user.save()
            print 'Setting role for user %s has done' % username
