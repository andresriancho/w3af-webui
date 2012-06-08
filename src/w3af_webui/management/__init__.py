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

def create_permission(codename, description):
    permission_content_type = ContentType.objects.get(
                            app_label='auth', name='permission')
    permission, created = Permission.objects.get_or_create(
                                     codename=codename,
                                     name=description,
                                     content_type=permission_content_type)
    return permission


def init_user_group(app, **kwargs):
    print 'init user group'
    if app != 'w3af_webui':
        return
    create_superuser()
    create_permission('view_all_data',
                      'Can use other user`s objects')
    # user groups
    need_groups_names = ('Scan', 'ScanProfile', 'ScanTask', 'Target',)
    for name in need_groups_names:
        group_name = '%s_%s_manage' % (app, name.lower())
        group, created = Group.objects.get_or_create(name=group_name)
        group.permissions.clear()
        content_type = ContentType.objects.get(app_label=app,
                                               model=name.lower())
        for permission in Permission.objects.filter(
                            content_type=content_type):
            group.permissions.add(permission)
        group.save()
    # w3af_webui_auth_manager
    group_name = '%s_auth_manage' % app
    group_obj, created = Group.objects.get_or_create(name=group_name)
    for permission in Permission.objects.filter(
                            content_type=ContentType.objects.filter(
                            app_label='auth', name='user')):
        group_obj.permissions.add(permission)
    # add stat_manager group
    view_stat = create_permission('view_stats',
                                  'Can use statistic reports')
    group_obj, created = Group.objects.get_or_create(name='%s_stat_manager' % app)
    group_obj.permissions.add(view_stat)

post_migrate.connect(init_user_group)
