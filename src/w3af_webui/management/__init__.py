# -*- coding: utf-8 -*-
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
    view_stat = create_permission('view_stats',
                                  'Can use statistic reports')
    # user groups
    for user_group in settings.USER_GROUPS:
        group_name = user_group['name']
        group, created = Group.objects.get_or_create(name=group_name)
        group.permissions.clear()
        for codename in user_group['permissions']:
            permission = Permission.objects.get(codename=codename)
            group.permissions.add(permission)
        group.save()

post_migrate.connect(init_user_group)
