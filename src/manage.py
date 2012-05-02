#!/usr/bin/env python
import sys
import os
_PATH = os.path.abspath(os.path.dirname(__file__))
sys.path[0:0] = [
    _PATH,
    _PATH + '/w3af_webui',
    #'/usr/lib/python2.6/dist-packages',
    ]

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE",
                          "w3af_webui.settings")
    from django.core.management import execute_from_command_line
    execute_from_command_line(sys.argv)
