#!/usr/bin/env python
import os
import sys
from subprocess import call
from subprocess import PIPE
from setuptools import setup
from setuptools.command.install import install as _install
dirs = ['w3af_web' + root.replace('/', '.')[3:]
        for root, dirs, files in os.walk('src/', topdown=False)
        if '.svn' not in root]
system_depends = [
    'w3af_console -h',
]
py_depends = {
        'lxml':'In Debian based systems just install python-lxml',
        'ghettoq':'You can install it from PyPI by easy_install ghettoq',
        'celery':'You can install it from PyPI by easy_install celery',
        'django_extensions':'You can install it from PyPI by easy_install django-extensions',
        'south':'You can install it from PyPI by easy_install south',
        'cronex':'You can get it from https://github.com/jameseric/cronex',
        'djcelery':'You can install it from PyPI by easy_install django-celery',
        'djkombu':'You can install it from PyPI by easy_install django-kombu',
        'MySQLdb':'In Debian based systems just install python-mysqldb',
}
py_version_depends = {
    'django': '1.4',
}
    
def check_py_dependencies():
    result = True
    for depend in py_depends:
        print 'check require %s....' % depend
        try:
            __import__(depend)
            print 'OK'
        except ImportError, e:
            print e, py_depends[depend]
            result = False
    return result

def check_version_dependencies():
    result = True
    for depend, version in py_version_depends.items():
        print 'check require %s version %s....' % (depend, version)
        try:
            import_module = __import__(depend)
            cur_version = import_module.get_version()
            if (version not in cur_version):
                print '%s %s was found but %s %s required' % (
                    depend,
                    cur_version,
                    depend,
                    version,
                ) 
                print 'Can not find %s %s' % (depend, version) 
                result = False
            else:
                print 'OK'
        except ImportError, e:
            print e
            result = False
    return result

def check_system_dependencies():
    result = True
    for depend in system_depends:
        print 'check require %s....' % depend
        try:
            retcode = call(depend, shell=True, stdout=PIPE)
            if retcode < 0:
                print "%s was terminated by signal %d" % (
                     depend, -retcode
                )
            else:
                print 'OK' 
        except OSError, e:
            print "Execution failed:", e
            result=False
    return result

class install(_install):
    def run(self):
        if (not check_system_dependencies() or
            not check_version_dependencies() or
            not check_py_dependencies()):
            print 'Can not find all requires'
            raise EnvironmentError
        _install.run(self)

setup(
    cmdclass={'install': install},
    name = "w3af_web",
    version = "1.0",
    url = 'http://w3af.org',
    license = 'GPLv2',
    description = "Web interface for w3af.",
    author = 'Svetlana Popova',
    author_email = 'svetleo@yandex-team.ru',
    packages = dirs,
    package_dir = {'w3af_web': 'src'},
    package_data = {'w3af_web.w3af_webui': 
                                ['templates/*.html',
                                'templates/admin/*.html',
                                'templates/admin/auth/*.html',
                                'templates/admin/w3af_webui/*.html',
                                'templates/admin/w3af_webui/target/*.html',
                                'locale/ru/LC_MESSAGES/*',
                                'static/w3af_webui/icons/*',
                                ]
    },
)
