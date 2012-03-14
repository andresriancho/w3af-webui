from __future__ import absolute_import

import os
import signal
from datetime import datetime
from logging import getLogger

from django.db import models
from django.contrib.auth.models import User
from django.utils.translation import ugettext_lazy as _
from django.conf import settings

from w3af_webui.tasks import scan_start

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

def generate_cron_daily(*args, **kwargs):
    if not kwargs['hour_min']:
        return ''
    return '%d %d * * *' % (
        kwargs['hour_min'].minute,
        kwargs['hour_min'].hour,
    )

def generate_cron_weekly(*args, **kwargs):
    if not kwargs['hour_min'] or not kwargs['weekday']:
        return ''
    return '%d %d * * %d' % (
        kwargs['hour_min'].minute,
        kwargs['hour_min'].hour,
        kwargs['weekday'],
    )

def generate_cron_monthly(*args, **kwargs):
    if not kwargs['hour_min'] or not kwargs['day']:
        return ''
    return '%d %d %d * *' % (
        kwargs['hour_min'].minute,
        kwargs['hour_min'].hour,
        kwargs['day'],
    )

def generate_cron_never(*args, **kwargs):
    return ''

class Profile(models.Model):
    user = models.OneToOneField(User, unique=True, related_name='profile')
    list_per_page = models.PositiveIntegerField(null=False, default=50)
    lang_ui = models.CharField(_('Interface language'),
                               choices=settings.LANGUAGES,
                               default='RU',
                               max_length=4)
    notification = models.IntegerField(_('Notification'),
                                       default=0,
                                       choices=settings.NOTIFY_STATUS)

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
    status = models.PositiveIntegerField(
                    _('Status'),
                    default=settings.TASK_STATUS[settings.TASK_STATUS_KEYS[0]],
                    choices=(list((settings.TASK_STATUS[k],_(k))
                    for k in settings.TASK_STATUS_KEYS)))
    start = models.fields.DateTimeField(_('Scan start'), null=True, blank=True)
    user = models.ForeignKey(User, verbose_name=_('User'), blank=True,
                            null=True)
    target = models.ForeignKey(Target, verbose_name=_('Target'))
    comment = models.CharField(_('Description'), blank=True, null=True,
                               max_length=255)
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
        permissions = (
            ("view_all_data", "Can view no only yourself tasks, scans,..etc"),)
    
    def __unicode__(self):
            return u'%s %s' % (self.comment, self.target,)
    
    def save(self, *args, **kwargs):
        try:
            self.user = kwargs['user']
            del kwargs['user']
        except Exception:
            pass
        repeat_period = self.repeat_each 
        functions = {1: generate_cron_never, 2: generate_cron_daily,
                     3: generate_cron_weekly, 4: generate_cron_monthly,}
        self.cron = functions.get(repeat_period, generate_cron_never)(
                        day=self.repeat_each_day,
                        weekday=self.repeat_each_weekday,
                        hour_min=self.repeat_at,
                    )
        if self.cron:
            logger.info('Setup cron string "%s" for scan id=%s '
                        '(repeat period is "%s")' % (
                            self.cron,
                            self.id,
                            repeat_period,
                        ))
        return super(ScanTask, self).save(*args, **kwargs)
    
    def create_scan(self):
        scan = Scan.objects.create(scan_task=self,
                                   start=datetime.now(),)
        self.status = settings.TASK_STATUS['lock']
        self.last_updated = datetime.now()
        self.save()
        return scan
    
    def run(self):
        scan = self.create_scan()
        try:
            scan_start.delay(scan.id)
        except Exception, e:
            print 'Scantask.run exception '
            logger.error('ScanTask run fail %s' % e)
            message = (' There was some problems with celery and '
                       ' this task was failed by find_scan celery task')
            scan.unlock_task(message)
            raise Exception, e

class ProfilesTargets(models.Model):
    id = models.AutoField(_('id'), primary_key=True)
    scan_profile = models.ForeignKey(ScanProfile,
                                     blank=True,
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
                                         null=True, )
    data = models.CharField(max_length=255, default='',
                            verbose_name = _('Report'),
                            null=True)
    pid = models.PositiveIntegerField(null=True, default=1)
    last_updated = models.DateTimeField(null=True,
                                        default=datetime(1991, 01, 01, 00, 00))
    result_message = models.CharField(max_length=1000, null=True, default='')
    
    def set_task_status_free(self):
        scan_task = self.scan_task
        scan_task.status = settings.TASK_STATUS['free']
        scan_task.save() 
    
    def unlock_task(self, text_comment='unlock task'):
        if self.status != settings.SCAN_STATUS['in_process']:
            return False
        kill_process(self.pid)
        self.set_task_status_free()
        self.status = settings.SCAN_STATUS['fail']
        self.result_message = text_comment
        self.save()
        return True 
    
    class Meta:
        verbose_name = _('scan')
        verbose_name_plural = _('scans')
        db_table = u'scans'
    
    def __unicode__(self):
        return u'%s' % (self.scan_task, )
    

