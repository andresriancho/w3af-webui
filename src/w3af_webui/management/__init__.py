# -*- coding: utf-8 -*-
from __future__ import absolute_import
from logging import getLogger

from django.contrib.auth.models import Group
from django.contrib.auth.models import User
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.conf import settings

from south.signals import post_migrate

logger = getLogger(__name__)

def create_superuser():
    try:
        superuser = User.objects.get(username=settings.SUPERUSER_NAME)
    except User.DoesNotExist:
        superuser = User.objects.create_user(
            settings.SUPERUSER_NAME,
            '%s@%s' % (settings.SUPERUSER_NAME, settings.APP_DOMAIN),
            settings.SUPERUSER_NAME,
            )
        logger.info('Create superuser "%s" <%s>' % (
                    superuser.username, superuser.email))
    superuser.is_superuser = True
    superuser.is_staff = True
    superuser.save()

def init_user_group(app, **kwargs):
    create_superuser()
    # user groups
    need_groups_names = ('Scan', 'ScanProfile', 'ScanTask', 'Target',)
    for name in need_groups_names:
        group_name = '%s_%s_manage' % (settings.PUG_PREFIX, name.lower())
        try:
            group = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            group = Group(name=group_name)
            group.save()
        group.permissions.clear()
        all_content_type = ContentType.objects.all()
        content_type = ContentType.objects.get(
                            app_label=app, model=name.lower())
        for permission in Permission.objects.filter(
                            content_type=content_type):
            group.permissions.add(permission)
        group.save()
    # w3af_webui_auth_manager
    for permission in Permission.objects.filter(
                            content_type=ContentType.objects.filter(
                            app_label='auth', name='user')):
        g_name = '%s_auth_manage' % settings.PUG_PREFIX
        try:
            ag = Group.objects.get(name=g_name)
        except Group.DoesNotExist:
            ag = Group(name=g_name)
            ag.save()
        ag.permissions.add(permission)
       

post_migrate.connect(init_user_group)

