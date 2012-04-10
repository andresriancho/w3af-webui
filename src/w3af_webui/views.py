# -*- coding: utf-8 -*-
import os
import urllib2
from logging import getLogger

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

from w3af_webui.models import ScanTask
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.tasks import scan_start

logger = getLogger(__name__)

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
        print 'exception run now %s' % e
        print scan.id
        scan.unlock_task()
        logger.error('run_row fail %s' % e)
        #message = (' There was some problems with celery and '
        #           ' this task was failed by find_scan celery task')
        #scan.unlock_task(message)
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
    print 'USER SETTINGS VIEW!'
    profile = request.user.get_profile()
    if request.method == 'POST':
        iface_lang = request.POST['iface_lang']
        profile.list_per_page = request.POST['list_per_page']
        profile.lang_ui = iface_lang
        profile.notification = request.POST['notification']
        profile.save()
        translation.activate(iface_lang)
        request.LANGUAGE_CODE = iface_lang
    class Form:
        __slots__ = ['list_per_page_code',
                     'iface_lang',
                     'notification',
                    ]
    form = Form()
    list_per_page_values = (
            ('10', '10'),
            ('30', '30'),
            ('50', '50'),
            ('70', '70'),
            ('90', '90'),
            ('100', '100'),
            )
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


@login_required
def show_report(request, scan_id):
    try:
        obj = Scan.objects.get(id=scan_id)
        if (not request.user.has_perm('w3af_webui.view_all_data') and
            obj.user != request.user):
            return HttpResponseForbidden()
        context = {'result_message': obj.result_message, }
        if os.access(obj.data , os.F_OK):
            context['report_link'] = obj.data
        return render_to_response("admin/show_report.html", context,
                                  context_instance=RequestContext(request))
    except Exception, e:
        print 'exception %s' % e
        raise Http404


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
