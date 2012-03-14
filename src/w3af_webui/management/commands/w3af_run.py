# -*- coding: utf-8 -*-
from __future__ import absolute_import

from os import makedirs
import sys
from tempfile import NamedTemporaryFile
from datetime import datetime
from time import sleep
from subprocess import Popen
from subprocess import PIPE
from logging import getLogger
import ConfigParser

from django.core.management.base import BaseCommand

from w3af_webui.models import ProfilesTasks
from w3af_webui.models import ProfilesTargets
from w3af_webui.models import Scan
from django.conf import settings

W3AF_POLL_PERIOD = 15 # seconds
logger = getLogger(__name__)

def send_notification(scan):
    notify_set =  scan.scan_task.user.get_profile().notification
    try:
        if settings.NOTIFY_MODULES[notify_set]['id'] == 'None': 
            # No notification
            return True
        notify_module = __import__(settings.NOTIFY_MODULES[notify_set]['module'],
                                   fromlist=[''])
        if 'notify' not in dir(notify_module):
            return False
        return notify_module.notify(scan.scan_task.user,
                                    scan.scan_task.target,
                                    scan.id)
    except Exception, e:
        logger.error('can not send notification: %s' % e)
        return False 

def get_profile(scan_task, report_path, report_file):
    profiles_tasks = ProfilesTasks.objects.filter(
                     scan_task__id=scan_task.id,
                     scan_profile__isnull=False).order_by('id')
    if not profiles_tasks:
        profiles_tasks = ProfilesTargets.objects.filter(
                         target__id=scan_task.target.id,
                         scan_profile__isnull=False).order_by('id')
    if not profiles_tasks:
        logger.error('No profiles found')
    profiles = [x.scan_profile for x in profiles_tasks ]
    profile_fh = NamedTemporaryFile(dir=report_path, delete=False,
                                    suffix='.pw3af')
    for profile in profiles:
        profile_text = profile.w3af_profile.splitlines()
        profile_fh.write('\n'.join(profile_text))
        profile_fh.write('\n')
    profile_fh.close()
    config = ConfigParser.RawConfigParser()
    config.optionxform = str
    config.read(profile_fh.name)
    try:
        config.add_section('target')
    except Exception, e:
        logger.error('can not add target section %s' % e)
    config.set('target', 'target', scan_task.target.url)
    try:
        config.add_section(settings.W3AF_OUTPUT_PLUGIN)
        config.add_section('output.textFile')
    except Exception, e:
        logger.error('can not add output plugin %s' % e)
    config.set(settings.W3AF_OUTPUT_PLUGIN, 'fileName', report_file)
    config.set('output.textFile', 'fileName', report_file[:-5] + '.txt')
    config.set('output.textFile', 'httpFileName',
               report_file[:-5] + '-http.txt')
    config.set('output.textFile', 'verbose', 'False')
    with open(profile_fh.name, 'wb') as configfile:
        config.write(configfile)
    print >> sys.stderr, profile_fh.name
    return profile_fh.name

def get_report_path():
    start = datetime.now()
    report_path = '%s/%s/%s/%s/'\
            % (settings.HTML_REPORT_UPLOAD, start.year, start.month, start.day)
    try:
        makedirs(report_path)
    except Exception, e:
        logger.info('Report path alresdy exist %s' % e)
    return report_path

def fail_scan(scan_id, message):
    '''set scan tatus to fail and set message to result_message '''
    scan = Scan.objects.get(pk=int(scan_id))
    previous_message = scan.result_message
    scan.result_message = previous_message + message
    scan.status = settings.SCAN_STATUS['fail']
    scan.save()
    scan.set_task_status_free()

def wait_process_finish(scan, process):
    scan.pid = process.pid
    scan.save()
    while process.returncode is None:
        scan.last_updated = datetime.today()
        scan.save()
        sleep(W3AF_POLL_PERIOD) # wail 
        process.poll() # get process status
    scan.set_task_status_free()
    scan.finish = datetime.now()
    scan.save()
    logger.info('w3af Process return code %s' % process.returncode)
    return process.returncode

class Command(BaseCommand):
    args = '<scan_id>'
    help = (u'command w3af_run start process w3af_console for defined scan_id')
    def handle(self, *args, **options):
        for scan_id in args:
            try:
                scan = Scan.objects.get(pk=int(scan_id))
                report_path = get_report_path()
                with NamedTemporaryFile(delete=False,
                                        suffix='.html',
                                        prefix='',
                                        dir=report_path) as output:
                    output.write('\nThere are not report from w3af\n')
                    output.close()
                    logger.info('Output file: %s' % output.name)
                    scan.start = datetime.now()
                    scan.data = output.name
                    scan.result_message = 'Scan in process now \n'
                    scan.save()
                    profile_fname = get_profile(scan.scan_task,
                                                report_path,
                                                output.name)
                    if (Scan.objects.get(pk=int(scan_id)).status != 
                        settings.SCAN_STATUS['in_process']):
                        return { } # scan was stopped by user
                    process = Popen([settings.W3AF_RUN, 
                                    '--no-update', '-P', 
                                    profile_fname],
                                    stdout=PIPE,
                                    stderr=PIPE)
                    returncode = wait_process_finish(scan, process)
                    if int(returncode) != 0:
                        # process terminated with error
                        fail_scan(scan_id,
                                  'w3af process return code %s' %
                                   returncode)
                        return {}
                    # process terminated successfully
                    scan.result_message = ''
                    if not send_notification(scan):
                        scan.result_message = 'Can not send notification'
                    scan.status = settings.SCAN_STATUS['done']
                    scan.save()
            except Scan.DoesNotExist:
                logger.error('scan object does not exist')
                raise Scan.DoesNotExist
            except Exception, e:
                logger.error('w3af_run exception: %s' % e)
                fail_scan(scan_id, ' w3af_run exception: %s' % e)
                raise Exception, e
                #raise CommandError('w3af scan fail %s' % e)
        return {}
