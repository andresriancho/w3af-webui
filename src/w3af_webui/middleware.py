# -*- coding: utf-8 -*- 
from __future__ import absolute_import

from django.utils import translation

class I18NMiddleware(object):
    def process_request(self, request):
        user = request.user
        if user.is_authenticated():
            lang = user.get_profile().lang_ui
            translation.activate(lang)
            request.LANGUAGE_CODE = lang
