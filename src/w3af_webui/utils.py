# -*- coding: utf-8 -*-

from django.db import DEFAULT_DB_ALIAS
 
def select_for_update(queryset):
    sql, params = queryset.query.get_compiler(DEFAULT_DB_ALIAS).as_sql()
    return queryset.model._default_manager.raw(sql + ' FOR UPDATE', params)
 
