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
import xml.etree.ElementTree as etree

from django.core.management.base import BaseCommand
from django.conf import settings

from w3af_webui.models import ProfilesTasks
from w3af_webui.models import ProfilesTargets
from w3af_webui.models import Scan
from w3af_webui.models import Vulnerability
from w3af_webui.models import VulnerabilityType
from w3af_webui.notification.send_mail import notify_about_fail

W3AF_POLL_PERIOD = 15 # seconds
logger = getLogger(__name__)

def send_notification(scan):
    '''
    Send notification using method notify from module,
    set as settings.NOTIFY_MODULES[notify_set]['module']
    '''
    notify_set =  scan.scan_task.user.get_profile().notification
    try:
        if settings.NOTIFY_MODULES[notify_set]['id'] == 'None':
            # No notification
            return True
        notify_module = __import__(settings.NOTIFY_MODULES[notify_set]['module'],
                                   fromlist=[''])
        if 'notify' not in dir(notify_module):
            return False
        return notify_module.notify(scan.user,
                                    scan.scan_task.target,
                                    scan.id)
    except Exception, e:
        logger.error('can not send notification: %s' % e)
        return False


def get_profile(scan_task, report_path, report_file):
    '''
    Agregate all included scan-profiles in one and added default plugins
    '''
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
        config.add_section(settings.W3AF_LOG_PLUGIN)
        config.add_section('output.xmlFile')
    except Exception, e:
        logger.error('can not add output plugin %s' % e)
    config.set(settings.W3AF_OUTPUT_PLUGIN, 'fileName', report_file)
    xml_report = report_file[:-5] + '.xml'
    config.set('output.xmlFile', 'fileName', xml_report)
    config.set(settings.W3AF_LOG_PLUGIN, 'fileName', report_file[:-5] + '.txt')
    config.set(settings.W3AF_LOG_PLUGIN, 'httpFileName',
               report_file[:-5] + '-http.txt')
    config.set(settings.W3AF_LOG_PLUGIN, 'verbose', 'False')
    with open(profile_fh.name, 'wb') as configfile:
        config.write(configfile)
    print >> sys.stderr, profile_fh.name
    return (profile_fh.name, xml_report)


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
    '''
    Set scan status to fail and set message to result_message
    '''
    print 'fail scan'
    scan = Scan.objects.get(pk=int(scan_id))
    previous_message = scan.result_message
    scan.result_message = previous_message + message
    scan.status = settings.SCAN_STATUS['fail']
    scan.finish = datetime.now()
    scan.save()
    scan.set_task_status_free()
    notify_set =  scan.scan_task.user.get_profile().notification
    if settings.NOTIFY_MODULES[notify_set]['id'] != 'None':
        notify_about_fail(scan.user,
                          scan.scan_task.target,
                          scan.id)


def save_vulnerabilities(scan, xml_report):
    '''
    Parse w3af xml output file, and save error ans vulnerabities from it ti db
    '''
    try:
        tree = etree.parse(xml_report)
        errors = list(tree.getiterator(tag='error'))
        errors_message = '<br>'.join(
                ['Error from %s: %s' %  (error.get('caller'), error.text)
                 for error in errors]
                 )
        scan.result_message = errors_message
        scan.save()
        if 'Error from w3afCore' in errors_message:
            return False
        for error in errors:
            caller = error.get('caller')
            error_text = error.text.strip() + '\n'
        issues = list(tree.getiterator(tag='vulnerability'))
        for issue in issues:
            severity = issue.get('severity')
            type_name = issue.get('plugin')
            vuln_type, created = VulnerabilityType.objects.get_or_create(
                                    name=type_name)
            description = issue.getiterator(tag='description')[0].text.strip()
            request = issue.getiterator(tag='httprequest')[0]
            status = request.getiterator(tag='status')[0]
            http_transaction = status.text.strip() + '\n'
            headers = request.getiterator(tag='headers')[0]
            header_list = list(headers.getiterator(tag='header'))
            for header in header_list:
                http_transaction += '%s: %s\n' % (
                        header.get('field').strip(),
                        header.get('content').strip(),
                                   )
            Vulnerability.objects.create(scan=scan,
                                         severity=severity,
                                         vuln_type=vuln_type,
                                         description=description,
                                         http_transaction=http_transaction,
                                         )
        return True
    except Exception, e:
        scan.result_message = 'Internal w3af_webui error in save vulnerabilies'
        scan.save()
        logger.error('Error in file w3af_run:save_vulnerabilities: '
                     'Cannot parse xml report for scan %s: %s' % (scan.id, e)
                    )
        return False


def post_finish(scan, returncode, xml_report):
    '''
    Change scan status to done if returncode and scan status is ok
    '''
    if int(returncode) == -9:
        # stoped by user, just return
        return
    if int(returncode) != 0:
        # process terminated with error or fail xml report
        fail_scan(scan.id,
                  'w3af process return code %s' % returncode)
        return
    # process terminated successfully
    if not save_vulnerabilities(scan, xml_report):
        fail_scan(scan.id, '')
        return
    # process was stoped by user
    if (Scan.objects.get(pk=int(scan.id)).status ==
        settings.SCAN_STATUS['fail']):
            return
    if not send_notification(scan):
        scan.result_message = 'Can not send notification'
    scan.status = settings.SCAN_STATUS['done']
    scan.save()


def wait_process_finish(scan, profile_fname):
    '''
    Start w3af process in new process, and wait while it terminate
    '''
    process = Popen([settings.W3AF_RUN,
                    '--no-update', '-P',
                    profile_fname],
                    stdout=PIPE,
                    stderr=PIPE)
    scan.pid = process.pid
    scan.save()
    while process.returncode is None:
        scan.last_updated = datetime.today()
        scan.save()
        sleep(W3AF_POLL_PERIOD) # wail 
        process.poll() # get process status
    scan.set_task_status_free()
    finish_time = datetime.now()
    scan.finish = finish_time
    scan.save()
    target = scan.scan_task.target
    target.last_scan = finish_time
    target.save()
    logger.info('w3af Process return code %s' % process.returncode)
    return process.returncode


class Command(BaseCommand):
    args = '<scan_id>'
    help = (u'command w3af_run start process w3af_console for defined scan_id')
    def handle(self, *args, **options):
        for scan_id in args:
            try:
                scan = Scan.objects.get(pk=int(scan_id))
                if (Scan.objects.get(pk=int(scan_id)).status !=
                    settings.SCAN_STATUS['in_process']):
                    return { } # scan was stopped by user
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
                    scan.save()
                    (profile_fname, xml_report) = get_profile(scan.scan_task,
                                                              report_path,
                                                              output.name)
                    returncode = wait_process_finish(scan, profile_fname)
                    post_finish(scan, returncode, xml_report)
                    #if os.access(xml_report, os.F_OK):
                    #    os.remove(xml_report)
            except Scan.DoesNotExist, e:
                logger.error('scan object does not exist %s' % e)
                raise Scan.DoesNotExist
            except Exception, e:
                logger.error('w3af_run exception: %s' % e)
                fail_scan(scan_id, ' w3af_run exception: %s' % e)
                raise
                #raise CommandError('w3af scan fail %s' % e)
        return {}
