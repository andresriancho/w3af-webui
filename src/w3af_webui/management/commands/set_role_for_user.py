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
                    default='manager',
                    help='Setup roles set for user(s): %s' %
                    settings.USER_ROLES
                    ),
        )

    def handle(self, *args, **options):
        user_examples = {}
        user_profiles = settings.USER_ROLES
        for username in args:
            user_examples[username] = user_profiles[options['role']]

        for username in user_examples.keys():
            new_user = None
            try:
                new_user = User.objects.get(username=username)
                logger.info("Update %s \"%s\" <%s>" % (
                            user_examples[username]['description'],
                            username,
                            user_examples[username]['email_prefix']))
            except User.DoesNotExist:
                new_user = User.objects.create_user(
                        username,
                        '',
                        username)
                logger.info("Create %s \"%s\" <%s>" % (
                            user_examples[username]['description'],
                            username,
                            user_examples[username]['email_prefix']))

            new_user.is_staff = True
            new_user.groups = []
            for group_name in user_examples[username]['groups']:
                full_group_name = '%s_%s' % (APP,
                                             group_name)
                try:
                    group_object = Group.objects.get(name=full_group_name)
                except Group.DoesNotExist:
                    print 'Wrong group name %s' % group_name
                    continue
                new_user.groups.add(group_object)
            new_user.save()
            print 'Setting role for user %s has done' % username

