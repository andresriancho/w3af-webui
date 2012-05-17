# -*- coding: utf-8 -*-
import os
import urllib2
import json
from logging import getLogger
from datetime import datetime
from datetime import date
import time
from qsstats import QuerySetStats

from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_protect
from django.template.context import RequestContext
from django.shortcuts import HttpResponse
from django.http import HttpResponseNotFound
from django.http import Http404
from django.http import HttpResponseForbidden
from django.shortcuts import render_to_response
from django.shortcuts import redirect
from django.utils import translation
from django.contrib.auth.decorators import login_required
from django.conf import settings
from django.utils.safestring import mark_safe
from django.contrib import messages

from w3af_webui.models import ScanTask
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.models import Vulnerability
from w3af_webui.tasks import scan_start

logger = getLogger(__name__)

list_per_page_values = (
            ('10', '10'),
            ('30', '30'),
            ('50', '50'),
            ('70', '70'),
            ('90', '90'),
            ('100', '100'),
            )

def r(request, template, **kwargs):
    return render_to_response(template,
                              kwargs,
                              context_instance=RequestContext(request))


def root(request):
    return redirect('/w3af_webui/scan/')


def run_now(request):
    if not 'id' in request.GET:
        raise Http404
    id = request.GET['id']
    scan_task = ScanTask.objects.get(id=id)
    scan = scan_task.create_scan(request.user)
    try:
        scan_start.delay(scan.id)
    except Exception, e:
        scan.unlock_task()
        logger.error('run_row fail %s' % e)
    return redirect('/w3af_webui/scantask/')


def stop_scan(request):
    if not 'id' in request.GET:
        raise Http404
    id = request.GET['id']
    obj = Scan.objects.get(id=id)
    message = 'Scan was stoped by user.'
    obj.unlock_task(message)
    return redirect(request.META['HTTP_REFERER'])


def get_select_code(select_value, data_array, element_id):
    result = '<select name="%s" id="%s">' % (element_id, element_id)
    for obj in data_array:
        selected = ''
        if str(select_value) == str(obj[0]):
            selected = u'selected="selected"'
        result += u'<option value="%s" %s>%s</option>' % (
            str(obj[0]),
            selected,
            obj[1],
        )
    result += u'</select>'
    return result

@csrf_protect
@login_required
def user_settings(request):
    profile = request.user.get_profile()
    if request.method == 'POST':
        iface_lang = request.POST['iface_lang']
        profile.lang_ui = iface_lang
        profile.list_per_page = request.POST['list_per_page']
        profile.notification = request.POST['notification']
        profile.save()
        translation.activate(iface_lang)
        request.LANGUAGE_CODE = iface_lang
        messages.success(request,
                         _('Your settings has been changed successfully'))
    class Form:
        __slots__ = ['list_per_page_code',
                     'iface_lang',
                     'notification',
                    ]
    form = Form()
    form.list_per_page_code = get_select_code(str(profile.list_per_page),
                                              list_per_page_values,
                                              'list_per_page')
    form.iface_lang = get_select_code(profile.lang_ui,
                                      settings.LANGUAGES,
                                      'iface_lang')
    form.notification = get_select_code(profile.notification,
                                        Profile.NOTIFY_STATUS,
                                        'notification')
    context = {'form': form, }
    return render_to_response("admin/user_settings.html", context,
            context_instance=RequestContext(request))


@login_required
def show_report_txt(request, scan_id):
    try:
        obj = Scan.objects.get(id=scan_id)
        if (not request.user.has_perm('w3af_webui.view_all_data') and
            obj.user != request.user):
            return HttpResponseForbidden()
        filename = obj.data[:-5] + '.txt'
        if os.access(filename , os.F_OK):
            f = open(filename, 'rb')
            return HttpResponse(f, mimetype='text/plain')
        return render_to_response("admin/show_report.html", { },
                                  context_instance=RequestContext(request))
    except:
        raise Http404


def get_vulnerability_module():
    post_module =  getattr(settings,
                           'VULN_POST_MODULE',
                           '')
    return __import__(post_module,
                      fromlist=[''])

@csrf_protect
@login_required
def post_vulnerability(request, scan_id):
    scan = Scan.objects.get(id=scan_id)
    if (not request.user.has_perm('w3af_webui.view_all_data') and
        scan.user != request.user):
        logger.info('fobbiden page for user %s' % request.user)
        return HttpResponseForbidden()
    if request.method == 'POST':
        vuln_id = request.POST['vuln_id']
        post_module = get_vulnerability_module()
        if 'post_vulnerability' in dir(post_module):
            if post_module.post_vulnerability(vuln_id, request.user):
                messages.success(request,
                                 _('This action finished successfully'))
            else:
                messages.error(request,
                               _('Someting go wrong. Cannot do this action'))
    return redirect('/show_report/%s/' % scan_id)


def get_filtered_vulnerabilities(scan, severity):
    allowed_values = settings.SEVERITY_DICT[severity]
    return Vulnerability.objects.filter(scan=scan,
                                        severity__in=allowed_values)


@csrf_protect
@login_required
def show_report(request, scan_id):
    scan = Scan.objects.get(id=scan_id)
    if (not request.user.has_perm('w3af_webui.view_all_data') and
        scan.user != request.user):
        logger.info('fobbiden page for user %s' % request.user)
        return HttpResponseForbidden()
    severity = request.GET.get('severity', 'all')
    class Issue:
        __slots__ = ['id',
                     'plugin',
                     'severity',
                     'desc',
                     'http_trans',
                    ]
    vuln_list = []
    vulnerabilities = get_filtered_vulnerabilities(scan, severity)
    for vuln in vulnerabilities:
        vulnerability = Issue()
        vulnerability.id = vuln.id
        vulnerability.plugin = vuln.vuln_type
        vulnerability.severity = vuln.severity
        vulnerability.desc = vuln.description
        vulnerability.http_trans = vuln.http_transaction
        vuln_list.append(vulnerability)
    severity_filter = get_select_code(severity,
                                      settings.SEVERITY_FILTER,
                                      'severity')
    context = {
       'target': scan.scan_task.target.url,
       'vulns': vuln_list,
       'severity_filter': severity_filter,
       'target_comment': scan.scan_task.target.comment,
    }
    template =  getattr(settings,
                        'VULNERABILITY_TEMPLATE',
                        'admin/w3af_webui/vulnerabilities.html')
    return render_to_response(template,
                              context,
                              context_instance=RequestContext(request))


@csrf_protect
def post_ticket(request):
    """
    View for your own module for vulnerability sending.
    """
    project = request.POST['project']
    summary = request.POST['summary']
    description = request.POST['description']
    priority = request.POST['priority']
    assignee = request.POST['assignee']
    cc_users = request.POST['cc']
    post_module = get_vulnerability_module()
    json_data = json.dumps({'status': 'fail',})
    if 'post_vulnerability' in dir(post_module):
        ticket_id, ticket_url = post_module.post_vulnerability(
                                             project,
                                             summary,
                                             description,
                                             assignee,
                                             cc_users=cc_users,
                                             priority=priority,
                                             reporter=request.user.username,)
        if ticket_id:
            json_data = json.dumps({
                'status': 'ok',
                'ticket_id': ticket_id,
                'ticket_url': ticket_url,
            })
    return HttpResponse(json_data, mimetype='json')


def check_url(request):
    url = request.GET.get('url', '') + '/'
    try:
        urllib2.urlopen(url)
        return HttpResponse('OK', mimetype='text/plain')
    except ValueError:
        return HttpResponseNotFound('ValueError')
    except urllib2.URLError, e:
        return HttpResponseNotFound('URLError %s' % e)
    return HttpResponseNotFound('Some check_url error')

@login_required
def reports(request):
    start_date = date(2012, 05, 1)
    end_date = datetime.now()
    queryset = Scan.objects.all()
    # scan count...
    qsstats = QuerySetStats(queryset,
                            date_field='start',
                            #aggregate=Count('id'),
                           )
    # ...per day
    values = qsstats.time_series(start_date, end_date, interval='days')
    #format_values = [ [x[0].strftime('%d-%m-%y'), x[1]] for x in values]
    # last_time =  int(time.mktime(fmtime.timetuple()) * 1000 + 4 * 3600000)
    format_values = []
    for x in values:
        fmtime = x[0].strftime('%d-%m-%y')
        format_date =  int(time.mktime(x[0].timetuple()) * 1000 + 4 * 3600000)
        format_values.append([format_date, x[1]])
    print format_values
    context = {'data': format_values } #[[0, 5], [1, 1], [2, 0], [3, 2]]}
    return render_to_response('admin/w3af_webui/reports.html',
                              context,
                              context_instance=RequestContext(request))
