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
            '',
            settings.SUPERUSER_NAME,
            )
        logger.info('Create superuser "%s" <%s>' % (
                    superuser.username, superuser.email))
    superuser.is_superuser = True
    superuser.is_staff = True
    superuser.save()


def create_extra_permission():
    codename = 'view_all_data'
    description = 'Can use other user`s objects'
    try:
        Permission.objects.get(codename=codename)
    except Permission.DoesNotExist:
        permission_content_type = ContentType.objects.get(
                            app_label='auth', name='permission')
        Permission.objects.create(codename=codename,
                                  name=description,
                                  content_type=permission_content_type)


def init_user_group(app, **kwargs):
    if app != 'w3af_webui':
        return
    create_superuser()
    create_extra_permission()
    # user groups
    need_groups_names = ('Scan', 'ScanProfile', 'ScanTask', 'Target',)
    for name in need_groups_names:
        group_name = '%s_%s_manage' % (app, name.lower())
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
        group_name = '%s_auth_manage' % app
        try:
            group_obj = Group.objects.get(name=group_name)
        except Group.DoesNotExist:
            group_obj = Group(name=group_name)
            group_obj.save()
        group_obj.permissions.add(permission)

post_migrate.connect(init_user_group)
