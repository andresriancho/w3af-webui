#-*- coding: utf-8 -*-
from __future__ import absolute_import
from logging import getLogger

from django.contrib import admin
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from django.conf import settings
from django.contrib.auth.admin import UserAdmin
from django.contrib.auth.models import User

from w3af_webui.models import ScanProfile
from w3af_webui.models import Target
from w3af_webui.models import ScanTask
from w3af_webui.models import Scan
from w3af_webui.models import ProfilesTasks
from w3af_webui.models import ProfilesTargets
from w3af_webui.models import Vulnerability
from w3af_webui.utils import delay_task_generator
from w3af_webui.utils import periodic_task_generator
from w3af_webui.utils import periodic_task_remove

logger = getLogger(__name__)

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


class CustomUserAdmin(UserAdmin):
    list_filter = ()
    list_display = (
                    'username',
                    'first_name',
                    'last_name',
                    'email',
                    'is_superuser',
                    )
    fieldsets = (
                ( _('Personal info'), {
                    'fields' : ('username',
                                'first_name',
                                'last_name',
                                'email', ),
                }),
                (_('Permissions'), {
                    'fields' : ('is_superuser',
                                'groups',
                               ),
                }),
    )

    def save_model(self, request, obj, form, change):
        obj.is_staff=True
        obj.save()


class W3AF_ModelAdmin(admin.ModelAdmin):
    """ Base class for ModelAdmin """
    def save_model(self, request, obj, form, change):
        if not obj.user:
            obj.user = request.user
        obj.save()

    def get_user(self, obj):
        return mark_safe(u"<a href='/auth/user/%s'>%s</a> " % (
               obj.user.id,
               obj.user.username,
               ))

    get_user.short_description = _('User')
    get_user.allow_tags = True
    get_user.admin_order_field = 'user__username'

    def changelist_view(self, request, extra_context=None):
        self.list_per_page = request.user.get_profile().list_per_page
        if (request.user.has_perm('w3af_webui.view_all_data') and
                                 'get_user' not in self.list_display):
            self.list_display.append('get_user')
            self.search_fields.append('user__username')
        if (not request.user.has_perm('w3af_webui.view_all_data') and
                                         'get_user' in self.list_display):
            self.list_display.remove('get_user')
            self.search_fields.remove('user__username')
        return super(W3AF_ModelAdmin, self).changelist_view(
                     request, extra_context)


class ScanProfileAdmin(W3AF_ModelAdmin):
    list_display = ['name', 'short_comment']
    search_fields = ['name', 'short_comment']

    def queryset(self, request):
        if(request.user.has_perm('w3af_webui.view_all_data')):
            return ScanProfile.objects.all()
        return ScanProfile.objects.filter(user=request.user)


    def has_delete_permission(self, request):
        return False

    def has_add_permission(self, request):
        return False


class ScanAdmin(W3AF_ModelAdmin):
    readonly_fields = ['scan_task_link', 'icon', 'get_target', ]
    search_fields = ['scan_task__name', 'scan_task__comment']
    list_display = ['icon', 'scan_task_link', 'comment', 'start', 'finish',
                    'report_or_stop','show_log', ]
    ordering = ('-id',)
    list_display_links = ('icon', )
    list_display_links = ('scan_task_link', )
    #list_display_links = ('report_or_stop', )
    actions = ['stop_action', 'delete_selected']

    def stop_action(self, request, queryset):
        for selected_obj in queryset:
            selected_obj.unlock_task()

    stop_action.short_description = u'%s' % _('Stop selected')

    def get_target(self, obj):
        return mark_safe(obj.scan_task.target)

    get_target.short_description = _('Target')

    def comment(self, obj):
        return mark_safe(obj.scan_task.comment)

    comment.short_description = _('Description')

    def stop_process(self, obj):
        if obj.status == settings.SCAN_STATUS['in_process']:
            return mark_safe(u'<a href="/stop_scan?id=%s">%s</a>' % (
                             obj.id,
                             _('Stop'),
                             ))
        return ''

    stop_process.short_description = _('Action')
    stop_process.allow_tags = True

    def scan_task_link(self, obj):
        return mark_safe(u'<a href="../scantask/%s/"> %s </a>' % (
                         obj.scan_task.id,
                         obj.scan_task.name,
                        ))

    scan_task_link.short_description = _('Task name')
    scan_task_link.allow_tags = True
    scan_task_link.admin_order_field = 'scan_task__name'

    def icon(self, obj):
        icons_status = {
            1: 'icon-in-proc.gif', # in process
            2: 'icon-yes.gif', # done
            3: 'icon-no.gif', # error
        }
        icon = icons_status.get(obj.status)
        return mark_safe(
            '<img src="%s/w3af_webui/icons/%s"/>' % (
            settings.STATIC_URL, icon,
            ))

    icon.short_description = _('Status')
    icon.allow_tags = True
    icon.admin_order_field = 'status'

    def report_or_stop(self, obj):
        if obj.status != settings.SCAN_STATUS['in_process']:
            return mark_safe(u'<a href="/show_report/%s/">%s</a>' %
                            (obj.id, _('Show report')))
        return mark_safe(u'<a href="/stop_scan?id=%s">%s</a>' %
                         (obj.id, _('Stop scan')))

    report_or_stop.short_description = _('Action')
    report_or_stop.allow_tags = True

    def show_log(self, obj):
        return mark_safe(
            u'<a target=_blanck href="/show_report_txt/%s/">%s</a>' %
            (obj.id, _('Show log'))
            )

    show_log.short_description = _('Show log')
    show_log.allow_tags = True

    def has_add_permission(self, request):
         return False

    def  queryset(self, request):
        if request.user.has_perm('w3af_webui.view_all_data'):
            return Scan.objects.all()
        return Scan.objects.filter(user=request.user)

    def change_view(self, request, object_id, extra_context=None):
        scan = Scan.objects.all().get(pk=object_id)
        extra_context = {'title': u'%s %s' % (
                                  _('Scan'),
                                  scan.scan_task.target.url,
                                  ) }
        return super(ScanAdmin, self).change_view(request, object_id,
                                                  extra_context)

    def changelist_view(self, request, extra_context=None):
        extra_context = {'title': u'%s' % _('Scans'), }
        self.list_per_page = request.user.get_profile().list_per_page
        return super(ScanAdmin, self).changelist_view(request,
                                                      extra_context)


class ProfileTargetInline(admin.StackedInline):
    '''for multiprofiles in task scan page '''
    model = ProfilesTargets
    extra = 1
    fieldsets = (
        (None, { 'classes': ('extrapretty' ),
        'fields': (( 'scan_profile'), )}), )


    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if (db_field.name == "scan_profile" and
            not request.user.has_perm('w3af_webui.view_all_data')):
            kwargs["queryset"] = ScanProfile.objects.filter(user=request.user)
        return super(ProfileTargetInline, self).formfield_for_foreignkey(
                    db_field, request, **kwargs)


class ProfileInline(admin.StackedInline):
    '''for multiprofiles in task scan page '''
    model = ProfilesTasks
    extra = 0
    fieldsets = (
        (None, { 'classes': ('extrapretty' ),
        'fields': (( 'scan_profile'), )}), )

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if (db_field.name == "scan_profile" and
            not request.user.has_perm('w3af_webui.view_all_data')):
            kwargs["queryset"] = ScanProfile.objects.filter(user=request.user)
        return super(ProfileInline, self).formfield_for_foreignkey(
                    db_field, request, **kwargs)


class ScanTaskAdmin(W3AF_ModelAdmin):
    '''Class for view scans in admin'''
    inlines = (ProfileInline, )
    list_display = ['name', 'target_name', 'comment', 'get_report', 'schedule',
                    'get_status', 'do_action', ]
    ordering = ('-id',)
    search_fields = ['name', 'comment', 'target__name', 'target__url',]
    fieldsets = (
                (None, {
                    'fields' : ('name', 'target', 'comment', 'start', ),
                }),
                (_('Repeating'), {
                    'classes': ('collapse',),
                    'fields' : ('repeat_each',
                               ('repeat_at',
                                'repeat_each_weekday',
                                'repeat_each_day',
                               ),),
                }),
    )

    def schedule(self, obj):
        if (obj.repeat_each !=
            settings.SCAN_REPEAT[settings.SCAN_REPEAT_KEYS[0]]):
            return _('Schedule')
        return _('One-time')

    schedule.short_description = _('Run regularity')
    schedule.allow_tags = True

    def get_status(self, obj):
        if obj.status == settings.TASK_STATUS['lock']:
            return  _('Active')
        return  _('Not active')

    get_status.short_description = _('Status')
    get_status.allow_tags = True

    def target_name(self, obj):
        return mark_safe(u'<a href="../target/%s/">'
                        u'%s</a>' % (obj.target.id, obj.target.name))

    target_name.short_description = _('target')
    target_name.allow_tags = True
    target_name.admin_order_field = 'target__name'

    def do_action(self, obj):
        if obj.status == settings.TASK_STATUS['lock']:
            scans = Scan.objects.filter(scan_task=obj.id,
                                        status=settings.SCAN_STATUS['in_process'])
            if len(scans) > 1:
                logger.error('There are more than one in-process report for'
                             'scan_task %s' % obj.id)
            if len(scans) == 1:
                return mark_safe(u'<a href="/stop_scan?id=%s">%s</a>' % (
                                 scans[0].id,
                                 _('Stop'),
                                ))
        return mark_safe(u'<a href="/run_now?id=%s">%s</a>' % (
                         obj.id,
                         _('Run now'),
                        ))

    do_action.short_description = _('Action')
    do_action.allow_tags = True

    def get_report(self, obj):
        try:
            scan = Scan.objects.filter(scan_task=obj.id).order_by('-start')[0]
            return mark_safe(u'<a href="/show_report/%s/">%s</a>' % (
                             scan.id,
                             scan.start
                            ))
        except:
            return ''

    get_report.short_description = _('Last scan')
    get_report.allow_tags = True

    def queryset(self, request):
        if request.user.has_perm('w3af_webui.view_all_data'):
            return ScanTask.objects.all()
        return ScanTask.objects.filter(user=request.user)

    def changelist_view(self, request, extra_context=None):
        extra_context = {'title': u'%s' % _('Tasks'), }
        return super(ScanTaskAdmin, self).changelist_view(request,
                                                          extra_context)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """choose targets only for current user"""
        if (db_field.name == "target" and
            not request.user.has_perm('w3af_webui.view_all_data')):
                kwargs["queryset"] = Target.objects.filter(user=request.user)
        return super(ScanTaskAdmin, self).formfield_for_foreignkey(
                     db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        obj.user = request.user
        if not obj.start and obj.id:
            periodic_task_remove('delay_%s' % obj.id)
        if obj.start:
            obj.save()
            delay_task_generator(obj.id, obj.start)
        functions = {1: generate_cron_never,
                     2: generate_cron_daily,
                     3: generate_cron_weekly,
                     4: generate_cron_monthly,}
        cron_string = functions.get(obj.repeat_each, generate_cron_never)(
                                            day=obj.repeat_each_day,
                                            weekday=obj.repeat_each_weekday,
                                            hour_min=obj.repeat_at,
                                            )
        if obj.cron != cron_string: # cron changed
            obj.save()
            obj.cron = cron_string
            if obj.cron:
                periodic_task_generator(obj.id, obj.cron)
            else:
                periodic_task_remove(obj.id)
        obj.save()


class TargetAdmin(W3AF_ModelAdmin):
    inlines = (ProfileTargetInline,)
    list_display = ['name', 'url', 'get_profiles', 'last_scan']
    search_fields = ['name', 'url']

    def get_profiles(self, obj):
        all_profiles = ProfilesTargets.objects.filter(target=obj)
        profile_names = [x.scan_profile.name for x in all_profiles]
        return ','.join(profile_names)

    get_profiles.short_description = _('Default scan profiles')
    get_profiles.allow_tags = True

    def queryset(self, request):
        if request.user.has_perm('w3af_webui.view_all_data'):
            return Target.objects.all()
        return Target.objects.filter(user=request.user)


admin.site.register(Target, TargetAdmin)
admin.site.register(ScanTask, ScanTaskAdmin)
admin.site.register(Scan, ScanAdmin)
admin.site.register(ScanProfile, ScanProfileAdmin)
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)
