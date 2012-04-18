from django.conf import settings
from django.test.simple import DjangoTestSuiteRunner
from django.utils.unittest.loader import defaultTestLoader
from django.test.simple import reorder_suite
from django.utils.importlib import import_module
from django.test import TestCase

class DiscoveryRunner(DjangoTestSuiteRunner):
    def build_suite(self, test_labels, extra_tests=None,
                        **kwargs):
        suite = None
        discovery_root = settings.TEST_DISCOVERY_ROOT
        if test_labels:
            suite = defaultTestLoader.loadTestsFromNames(
                            test_labels)
            if not suite.countTestCases() and len(test_labels) == 1:
                suite = None
                discovery_root = import_module(test_labels[0]).__path__[0]

        if suite is None:
            suite = defaultTestLoader.discover(
                        discovery_root,
                        top_level_dir=settings.BASE_PATH,
                        )
        if extra_tests:
            for test in extra_tests:
                suite.addTest(test)
        return reorder_suite(suite, (TestCase,))
