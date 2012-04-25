#-*- coding: utf-8 -*-
from datetime import datetime
from datetime import time
from subprocess import Popen
from subprocess import PIPE
from mock import patch

from django.test import TestCase
from django_any.models import any_model
from django.conf import settings
from django.utils import unittest
from django.test.client import Client
from django.core.management import call_command
from django.contrib.auth.models import User
from django.core import mail

from w3af_webui.models import ScanTask
from w3af_webui.models import Target
from w3af_webui.models import ScanProfile
from w3af_webui.models import Scan
from w3af_webui.models import Profile
from w3af_webui.management import init_user_group


