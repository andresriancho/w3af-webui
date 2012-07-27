# -*- coding: utf-8 -*-
import os
import urllib2
import simplejson as json
from logging import getLogger
from datetime import datetime
from datetime import date
from datetime import timedelta
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
from django.db.models import Sum
from django.db.models import Count
from django.utils.encoding import smart_str
from django.db.models import Q


from w3af_webui.models import ScanTask
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.models import ProfilesTargets
from w3af_webui.models import Target
from w3af_webui.models import Vulnerability
from w3af_webui.models import VulnerabilityType
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


def scan_start_callback(scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.unlock_task()
    logger.error('scan fail by scan_start_callback')


def run_now(request):
    if not 'id' in request.GET:
        raise Http404
    id = request.GET['id']
    try:
        # create scan here and run scan task (not scan_create_task) for 
        # view immediatelly  scan_task status=run
        scan_task = ScanTask.objects.get(id=id)
        scan = scan_task.create_scan(request.user)
    except Exception, e:
        logger.error('run now function fail: %s' % e)
    else:
        fun = scan_start_callback
        scan_start.delay(scan.id, fun)
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
    class Issue:
        __slots__ = ['id',
                     'plugin',
                     'severity',
                     'desc',
                     'http_trans',
                     'is_false_positive',
                    ]
    allowed_values = settings.SEVERITY_DICT[severity]
    vulnerabilities = Vulnerability.objects.filter(
                            scan=scan,
                            severity__in=allowed_values,
                            )
    vuln_list = []
    for vuln in vulnerabilities:
        vulnerability = Issue()
        vulnerability.id = vuln.id
        vulnerability.plugin = vuln.vuln_type
        vulnerability.severity = vuln.severity
        vulnerability.desc = vuln.description
        vulnerability.http_trans = vuln.http_transaction
        vulnerability.is_false_positive = vuln.is_false_positive
        vuln_list.append(vulnerability)
    return vuln_list


@csrf_protect
@login_required
def show_report(request, scan_id):
    scan = Scan.objects.get(id=scan_id)
    if (not request.user.has_perm('w3af_webui.view_all_data') and
        scan.user != request.user):
        logger.info('fobbiden page for user %s' % request.user)
        return HttpResponseForbidden()
    if (scan.user == request.user and scan.show_report_time is None):
        scan.show_report_time = datetime.now()
        scan.save()
    severity = request.GET.get('severity', 'all')
    vuln_list = get_filtered_vulnerabilities(scan, severity)
    severity_filter = get_select_code(severity,
                                      settings.SEVERITY_FILTER,
                                      'severity')
    context = {
       'target': scan.scan_task.target.url,
       'vulns': vuln_list,
       'severity_filter': severity_filter,
       'target_comment': scan.scan_task.target.comment,
       'error_message': scan.result_message.split("<br>"),
    }
    template = getattr(settings,
                        'VULNERABILITY_TEMPLATE',
                        'admin/w3af_webui/vulnerabilities.html')
    return render_to_response(template,
                              context,
                              context_instance=RequestContext(request))


@csrf_protect
def mark_vuln_false_positive(request):
    """
    View for ajax request for mark vulnerability as false positive
    """
    return HttpResponse(json.dumps({'status': 'fail', }), mimetype='json')
    vuln_id = request.POST['vuln_id']
    try:
        vuln = Vulnerability.objects.get(pk=vuln_id)
        vuln.is_false_positive = not vuln.is_false_positive
        vuln.save()
        json_data = json.dumps({
            'status': 'ok',
            'is_positive': vuln.is_false_positive,
        })
    except:
        json_data = json.dumps({
            'status': 'fail',
        })
    return HttpResponse(json_data, mimetype='json')


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


def date_to_milliseconds(dt):
    return int(time.mktime(dt.timetuple()) * 1000 + 4 * 3600000)


def format_date(lst):
    """lst = [[Date1, value1], [Date2, value2],...]"""
    return [[date_to_milliseconds(x[0]), x[1]]
            for x in lst]


def get_last_scan_vuln(TOP_LIMIT):
    last_scan_vuln_qs = Vulnerability.objects.raw(
        'SELECT v.id, last_scan.target_name, last_scan.target_id '
        'as target_id, count(v.id) AS cnt FROM '
        '(SELECT max(s.id) AS id, MAX(s.start), target_id, t.name as '
        'target_name FROM scans s JOIN scan_tasks st ON (s.scan_task_id '
        '= st.id) JOIN targets t ON (st.target_id = t.id) WHERE s.status=%s '
        'GROUP BY target_id) last_scan JOIN vulnerabilities v on (v.scan_id '
        '= last_scan.id) GROUP BY last_scan.id ORDER BY cnt DESC limit %s',
         [settings.SCAN_STATUS['done'], TOP_LIMIT])
    last_scan_vuln = json.dumps(
            [{'label': v.target_id,
              'data': [ [i, int(v.cnt)], ] }
            for i, v in enumerate(last_scan_vuln_qs)]
    )
    last_scan_vuln_label = json.dumps(
                        [[i, v.target_name.encode('utf-8')]
                        for i, v in enumerate(last_scan_vuln_qs)]
    )
    return (last_scan_vuln, last_scan_vuln_label)


def get_last_scan_critic_vuln(TOP_LIMIT):
    last_scan_vuln_qs = Vulnerability.objects.raw(
        'SELECT v.id, last_scan.target_name, last_scan.target_id '
        'as target_id, sum(v.severity="Hight") AS cnt FROM '
        '(SELECT max(s.id) AS id, MAX(s.start), target_id, t.name as '
        'target_name FROM scans s JOIN scan_tasks st ON (s.scan_task_id '
        '= st.id) JOIN targets t ON (st.target_id = t.id) WHERE s.status=%s '
        'GROUP BY target_id) last_scan JOIN vulnerabilities v on (v.scan_id '
        '= last_scan.id) GROUP BY last_scan.id ORDER BY cnt DESC limit %s',
         [settings.SCAN_STATUS['done'], TOP_LIMIT])
    last_scan_vuln = json.dumps(
            [{'label': v.target_id,
              'data': [
                      [i, int(v.cnt) if v.cnt is not None else 0 ],]
             } for i, v in enumerate(last_scan_vuln_qs)]
    )
    last_scan_vuln_label = json.dumps([[i, v.target_name.encode('utf-8')]
                       for i, v in enumerate(last_scan_vuln_qs)])
    return (last_scan_vuln, last_scan_vuln_label)


def get_target_not_show_report(TOP_LIMIT):
    # top targets with max count of unshow report (only successfull scans)
    top_not_show_qs = Target.objects.raw('SELECT t.id, t.name, '
        'COUNT(DISTINCT(s.id)) AS cnt FROM vulnerabilities v JOIN scans s ON '
        '(scan_id = s.id) JOIN scan_tasks st ON (s.scan_task_id = st.id) '
        'JOIN targets t ON (st.target_id = t.id) WHERE s.show_report_time '
        'IS NULL GROUP BY t.id ORDER BY cnt DESC limit %s;', [TOP_LIMIT])
    top_not_show_report = json.dumps(
                            [{'label': v.id,
                            'data': [ [i, int(v.cnt)], ] }
                            for i, v in enumerate(top_not_show_qs)]
    )
    top_not_show_report_label = json.dumps(
                                [[i, v.name.encode('utf-8')]
                                for i, v in enumerate(top_not_show_qs)]
    )
    return (top_not_show_report, top_not_show_report_label)


def get_target_downtime(TOP_LIMIT):
    downtime_qs = Target.objects.raw('SELECT t.id, t.name, TO_DAYS(NOW()) - '
        'TO_DAYS(max(s.start)) AS downtime FROM  scans s JOIN scan_tasks st '
        'ON (s.scan_task_id = st.id) join targets t on (st.target_id = t.id) '
        'WHERE s.status = %s GROUP BY target_id ORDER BY downtime DESC '
        'limit %s;', [settings.SCAN_STATUS['done'], TOP_LIMIT] )
    downtime = json.dumps(
                    [{'label': v.id,
                    'data': [ [i, int(v.downtime)], ] }
                    for i, v in enumerate(downtime_qs)]
    )
    downtime_label = json.dumps(
                    [[i, v.name.encode('utf-8')]
                    for i, v in enumerate(downtime_qs)]
    )
    return(downtime, downtime_label)


def get_scan_per_day(start_date, end_date):
    scan_qsstats = QuerySetStats(Scan.objects.all(),
                                 date_field='start',)
    scan_values = scan_qsstats.time_series(start_date, end_date, interval='days')
    return format_date(scan_values)


def get_all_vuln(start_date, target=None):
    # All type
    scan_qset = Scan.objects.filter(start__gte=start_date)
    if target:
        scan_qset = Scan.objects.filter(scan_task__target=target,
                                        start__gte=start_date)
    all_type_qset = scan_qset.annotate(cnt=Count('vulnerability')
                                      ).order_by('start')
    vuln_count = format_date([[x.start, int(x.cnt) ] for x in all_type_qset])
    return {'label': 'all',
            'data': vuln_count,
    }


def get_vuln_by_type(start_date):
    result = [get_all_vuln(start_date)] # all type
    # Each type separatly
    for vuln_type in VulnerabilityType.objects.all():
        scan_qset = Scan.objects.raw('SELECT s.id, s.start,'
        'SUM(IF(v.vuln_type_id=%s,1,0)) AS cnt,'
        ' v.vuln_type_id AS vuln_type FROM scans s LEFT JOIN vulnerabilities v '
        'on (s.id = v.scan_id) JOIN scan_tasks st on (s.scan_task_id = st.id'
        ') WHERE s.start>=%s GROUP BY s.id',
        [vuln_type.id, start_date.strftime("%Y%m%d")])
        vuln_count = format_date([[x.start, int(x.cnt) ] for x in scan_qset])
        result.append({'label': vuln_type.name.encode('utf8'),
                       'data': vuln_count,
        })
    return result


def get_active_target(start_date, end_date):
    start_active_date = start_date - timedelta(days=90)
    end_active_date = start_date
    active_count = []
    while (end_active_date <= end_date):
        active_target_qs = Scan.objects.raw('SELECT s.id, '
            'COUNT(DISTINCT(target_id)) AS cnt FROM scans s JOIN scan_tasks '
            'st ON (s.scan_task_id = st.id) JOIN targets t ON (st.target_id '
            '= t.id)  WHERE s.start >= %s AND s.start <= %s AND s.status = %s '
            'AND s.show_report_time is not null',
            [start_active_date.strftime("%Y%m%d"),
            end_active_date.strftime("%Y%m%d"),
            settings.SCAN_STATUS['done'],
        ])
        if active_target_qs[0].cnt:
            active_count.append([date_to_milliseconds(end_active_date),
                            int(active_target_qs[0].cnt)])
        start_active_date += timedelta(days=1)
        end_active_date += timedelta(days=1)
    return active_count


@login_required
def stats(request):
    end_date = date.today()
    start_date = end_date - timedelta(days=92)
    one_year_ago = end_date - timedelta(days=365)
    TOP_LIMIT = 5
    last_scan_vuln, last_scan_vuln_label =  \
                                get_last_scan_vuln(TOP_LIMIT)
    last_scan_critic_vuln, last_scan_critic_vuln_label =  \
                                get_last_scan_critic_vuln(TOP_LIMIT)
    # top targets with max count of unshow report (only successfull scans)
    not_show_report, not_show_report_label =\
                                get_target_not_show_report(TOP_LIMIT)
    # top target - time after last scan
    downtime, downtime_label = get_target_downtime(TOP_LIMIT)
    # scan per day
    scan_count = get_scan_per_day(start_date, end_date)
    # vulnerabilities per day
    vuln_count = get_vuln_by_type(start_date)
    # active target count
    active_target = get_active_target(one_year_ago, end_date)
    context = {
              'last_scan_vuln': last_scan_vuln,
              'last_scan_vuln_label': last_scan_vuln_label,
              'last_scan_critic_vuln': last_scan_critic_vuln,
              'last_scan_critic_vuln_label': last_scan_critic_vuln_label,
              'top_not_show_report': not_show_report,
              'top_not_show_report_label': not_show_report_label,
              'downtime': downtime,
              'downtime_label': downtime_label,
              'scan_count': scan_count,
              'vuln_count': vuln_count,
              'active_target': active_target,
               }
    return render_to_response('admin/w3af_webui/stats.html',
                              context,
                              context_instance=RequestContext(request))


def get_vuln_count_by_severity_for_target(target, start_date):
    result = [get_all_vuln(start_date, target)] # all type
    severity_queryset = Vulnerability.objects.values(
                        'severity').distinct('severity')
    for vuln in severity_queryset:
        scan_queryset = Scan.objects.raw('SELECT s.id, s.start, '
        'SUM(IF(v.severity=%s,1,0)) AS cnt, '
        'v.severity AS severity FROM scans s LEFT JOIN vulnerabilities v '
        'on (s.id = v.scan_id) JOIN scan_tasks st on (s.scan_task_id = st.id'
        ') WHERE st.target_id=%s AND s.start>=%s '
        'GROUP BY s.id',
        [vuln['severity'], target.id, start_date.strftime("%Y%m%d")])
        data = format_date([[x.start,int(x.cnt)] for x in scan_queryset])
        result.append({'label': vuln['severity'].encode('utf-8'),
                       'data': data,
        })
    return result


def get_vuln_count_by_type_for_target(target, start_date):
    result =  [get_all_vuln(start_date, target)] # all type
    for vuln_type in VulnerabilityType.objects.all():
        queryset = Scan.objects.raw('SELECT s.id, s.start,'
        'SUM(IF(v.vuln_type_id=%s,1,0)) AS cnt,'
        ' v.vuln_type_id AS vuln_type FROM scans s LEFT JOIN vulnerabilities v '
        'on (s.id = v.scan_id) JOIN scan_tasks st on (s.scan_task_id = st.id'
        ') WHERE st.target_id=%s AND s.start>=%s  '
        ' GROUP BY s.id',
        [vuln_type.id, target.id, start_date.strftime("%Y%m%d")])
        data = format_date([[x.start, int(x.cnt)] for x in queryset])
        result.append({'label': vuln_type.name.encode('utf8'),
                       'data': data,
        })
    return result


def not_show_time_for_target(target_id, start_date):
    not_show_time_qs = Scan.objects.raw('SELECT s.id, s.start, TO_DAYS(NOW())'
        ' - TO_DAYS(s.finish) as now_minus_finish, TO_DAYS(s.show_report_time)'
        ' - TO_DAYS(s.finish) as show_minus_finish from scans s JOIN '
        'scan_tasks st on (s.scan_task_id = st.id) WHERE st.target_id=%s AND '
        's.status = %s AND s.start>=%s ORDER BY s.start',
        [target_id, settings.SCAN_STATUS['done'],
        start_date.strftime("%Y%m%d"),
    ])
    data = format_date([[x.start,
                        int(x.show_minus_finish)
                        if x.show_minus_finish is not None
                        else int(x.now_minus_finish)]
                        for x in not_show_time_qs
    ])
    return [data]


@login_required
def target_stats(request, target_id):
    target = Target.objects.get(pk=target_id)
    if (not request.user.has_perm('w3af_webui.view_all_data') and
        target.user != request.user):
        logger.info('fobbiden page for user %s' % request.user)
        return HttpResponseForbidden()
    profiles = ProfilesTargets.objects.filter(target=target)
    profiles_str = ", ".join([x.scan_profile.name for x in profiles])
    end_date = datetime.now()
    start_date = end_date - timedelta(days=92)
    context = {
               'vuln_count_by_type':
                   get_vuln_count_by_type_for_target(target, start_date),
               'vuln_count_by_severity':
                   get_vuln_count_by_severity_for_target(target, start_date),
               'not_show_time':
                   not_show_time_for_target(target_id, start_date),
               'target': target,
               'profiles': profiles_str,
    }
    return render_to_response('admin/w3af_webui/target_stats.html',
                              context,
                              context_instance=RequestContext(request))

