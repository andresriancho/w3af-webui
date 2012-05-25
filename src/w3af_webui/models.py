from __future__ import absolute_import

import os
import signal
from datetime import datetime
from logging import getLogger

from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

logger = getLogger(__name__)

def kill_process(str_pid):
    try:
        pid = int(str_pid)
        if pid == 1: #default value, process did not start
            return False
        os.kill(pid, signal.SIGKILL)
        return True
    except Exception, e:
        logger.error('models.kill_process error: can not kill process: %s' % e)
        return False


class Profile(models.Model):
    NOTIFY_STATUS = tuple((ind, value['label'])
                     for ind, value in enumerate(settings.NOTIFY_MODULES))

    user = models.OneToOneField(User, unique=True, related_name='profile')
    list_per_page = models.PositiveIntegerField(null=False, default=50)
    lang_ui = models.CharField(_('Interface language'),
                               choices=settings.LANGUAGES,
                               default=settings.DEFAULT_LANGUAGE,
                               max_length=4)
    notification = models.IntegerField(_('Notification'),
                                       default=0,
                                       choices=NOTIFY_STATUS)

    class Meta:
        db_table = u'w3af_webui_profile'


def create_profile(sender, **kwargs):
    if kwargs['created']:
        Profile.objects.create(user=kwargs['instance'])


models.signals.post_save.connect(create_profile, sender=User)


class ScanProfile(models.Model):
    '''Scan profiles here'''
    id = models.AutoField(_('id'), primary_key=True)
    name = models.CharField(_('Name'), unique=True, max_length=240)
    short_comment = models.CharField(_('Short description'), blank=True,
                                     max_length=240)
    w3af_profile = models.TextField(_('w3af-profile'), blank=True,
                                    default=settings.SCAN_DEFAULT_PROFILE)
    user = models.ForeignKey(User, verbose_name=_('User'),
                             blank=True, null=True)

    class Meta:
        verbose_name = _('scan profile')
        verbose_name_plural = _('Scan profiles')
        db_table = u'scan_profiles'

    def __unicode__(self):
        return u'%s' % self.name


class Target(models.Model):
    '''Targets for scanning'''
    id = models.AutoField(_('id'), primary_key=True)
    name = models.CharField(_('Name'), unique=True, max_length=240)
    url = models.CharField(_('URL'), max_length=240,
                           help_text= u'<p class=checkRes></p>')
    comment = models.CharField(settings.TARGET_COMMENT_LABEL,
                               max_length=32, blank=True, null=True)
    user = models.ForeignKey(User, verbose_name=_('User'), blank=True,
                             null=True)
    last_scan = models.fields.DateTimeField(_('Last scan date'),
                                            blank=True,
                                            null=True,
                                            editable=False)

    class Meta:
        verbose_name = _('target')
        verbose_name_plural = _('Targets')
        db_table = u'targets'

    def __unicode__(self):
        return u'%s' % self.name


class ScanTask(models.Model):
    '''Scan jobs'''
    id = models.AutoField(_('id'), primary_key=True)
    name = models.CharField(_('Task name'), max_length=64, null=True)
    status = models.PositiveIntegerField(
                    _('Status'),
                    default=settings.TASK_STATUS[settings.TASK_STATUS_KEYS[0]],
                    choices=(list((settings.TASK_STATUS[k], k)
                    for k in settings.TASK_STATUS_KEYS)))
    start = models.fields.DateTimeField(_('Scan start'), null=True, blank=True)
    user = models.ForeignKey(User, verbose_name=_('User'), blank=True,
                             null=True)
    target = models.ForeignKey(Target, verbose_name=_('Target'))
    comment = models.TextField(_('Description'), blank=True, null=True,
                               max_length=500)
    cron = models.CharField(_('Cron string'), blank=True, null=True,
                            max_length=64)
    repeat_at = models.fields.TimeField(_('Time'), null=True, blank=True)
    repeat_each = models.PositiveIntegerField(
                    _('Repeat each'),
                    default=settings.SCAN_REPEAT[settings.SCAN_REPEAT_KEYS[0]],
                    choices=( list((settings.SCAN_REPEAT[k], k)
                    for k in settings.SCAN_REPEAT_KEYS) ) )
    repeat_each_day = models.IntegerField(
                              _('Day number'),
                              null=True,
                              blank=True,
                              choices=(list( (k, k) for k in range(1, 32))))
    repeat_each_weekday = models.IntegerField(
                            _('Day of week'), null=True, blank=True,
                            choices=(list((k + 1, settings.WEEK_DAY_NAME[k])
                            for k in range(0, len(settings.WEEK_DAY_NAME)))))

    class Meta:
        verbose_name = _('scan task')
        verbose_name_plural = _('scan tasks')
        db_table = u'scan_tasks'
        #permissions = (
        #    ("view_all_data", "Can view no only yourself tasks, scans,..etc"),)

    def __unicode__(self):
        return u'%s' % (self.name)
        #return u'<a href="../scantask/%s/"> %s</a>' % (
        #                 self.id,
        #                 self.name,
        #                )


    def create_scan(self, user):
        scan = Scan.objects.create(scan_task=self,
                                   start=datetime.now(),
                                   user=user)
        self.status = settings.TASK_STATUS['lock']
        self.last_updated = datetime.now()
        self.save()
        return scan


class ProfilesTargets(models.Model):
    id = models.AutoField(_('id'), primary_key=True)
    scan_profile = models.ForeignKey(ScanProfile,
                                     blank=False,
                                     verbose_name=_('Profile'))
    target = models.ForeignKey(Target,
                               blank=True,
                               verbose_name=_('Target'))

    class Meta:
        verbose_name        = _('Default scan profile')
        verbose_name_plural = _('Default scan profiles')
        db_table            = u'profiles_targets'

    def __unicode__(self):
        return u'%s' % self.scan_profile


class ProfilesTasks(models.Model):
    id = models.AutoField(_('id'), primary_key=True)
    scan_profile = models.ForeignKey(ScanProfile,
                                     blank=False,
                                     verbose_name=_('Profile'))
    scan_task = models.ForeignKey(ScanTask,
                                  blank=True,
                                  verbose_name=_('Scan'))

    class Meta:
        verbose_name        = _('Profile')
        verbose_name_plural = _('Profiles')
        db_table            = u'profiles_tasks'

    def __unicode__(self):
        return u'%s' % (self.scan_profile, )


class Scan(models.Model):
    '''Reports for scans'''
    id = models.AutoField(_('id'), primary_key=True)
    scan_task = models.ForeignKey(ScanTask, verbose_name=_('Scan task'))
    status = models.PositiveIntegerField(
                    _('Status'), editable=True,
                    default=settings.SCAN_STATUS[settings.SCAN_STATUS_KEYS[0]],
                    choices=(list((settings.SCAN_STATUS[k],_(k))
                    for k in settings.SCAN_STATUS_KEYS)))
    start = models.fields.DateTimeField(_('Scan start'),
                                        default=datetime.now())
    finish = models.fields.DateTimeField(_('Scan finish'),
                                         blank=True,
                                         null=True,)
    data = models.CharField(max_length=255, default='',
                            verbose_name = _('Report'),
                            null=True)
    pid = models.PositiveIntegerField(null=True, default=1)
    last_updated = models.DateTimeField(null=True,
                                        default=datetime(1991, 01, 01, 00, 00))
    result_message = models.CharField(max_length=1000, null=True, default='')
    user = models.ForeignKey(User, verbose_name=_('User'), blank=True,
                             null=True)


    def set_task_status_free(self):
        scan_task = self.scan_task
        scan_task.status = settings.TASK_STATUS['free']
        scan_task.save()

    def unlock_task(self, text_comment='Internal error'):
        if self.status != settings.SCAN_STATUS['in_process']:
            return False
        kill_process(self.pid)
        self.set_task_status_free()
        self.status = settings.SCAN_STATUS['fail']
        self.result_message = text_comment
        self.finish = datetime.now()
        self.save()
        logger.info('scan %s was failed' % self.id)
        return True

    class Meta:
        verbose_name = _('scan')
        verbose_name_plural = _('scans')
        db_table = u'scans'
        #ordering = ['-start']

    def __unicode__(self):
        return u'%s' % (self.scan_task, )


class VulnerabilityType(models.Model):
    id = models.AutoField(_('id'), primary_key=True)
    name = models.CharField(_('Type of vulnerability'), max_length=80)

    def __unicode__(self):
        return u'%s' % self.name

    class Meta:
        verbose_name = _('Type of vulnerability')
        verbose_name_plural = _('Types of vulnerability')
        db_table = u'vulnerability_types'


class Vulnerability(models.Model):
    id = models.AutoField(_('id'), primary_key=True)
    scan = models.ForeignKey(Scan, verbose_name=_('Scan'))
    severity = models.CharField(_('Severity'), max_length=30,
                               null=True)
    vuln_type = models.ForeignKey(VulnerabilityType,
                                  verbose_name=_('Vulnerability type'),
                                  null=True)
    description = models.TextField(_('Description'), blank=True, null=True)
    http_transaction = models.TextField(_('HTTP Transaction'),
                                        blank=True,
                                        null=True,
                                        )

    def __unicode__(self):
        return u'%s' % self.vuln_type

    class Meta:
        verbose_name = _('Vulnerability')
        verbose_name_plural = _('Vulnerabilities')
        db_table = u'vulnerabilities'

