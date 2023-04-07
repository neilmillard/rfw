#!/usr/bin/env python
#
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)  
#
# This file is part of rfw
#
# The MIT License (MIT)
#
# Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead. 
# Fight intellectual "property".
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import io
import os
import re
import sys

from setuptools import setup
from setuptools.command.install import install

pytver = sys.version_info

if pytver[0] == 3 and pytver[1] >= 7:
    pass
else:
    print("rfw requires python 2.7")
    sys.exit(1)


# post install hook
class post_install(install):
    def run(self):
        # call parent
        install.run(self)
        # custom post install message
        print('\n\nBefore running rfw you must generate or import certificates. See /etc/rfw/deploy/README.rst\n\n')
        print(
            'To install the RFW system script, please run \n\n\t\tupdate-rc.d rfw defaults\n\t\tchmod +x /etc/init.d/rfw\n')


# Utility function to read the README file used for long description.
def read(*filenames, **kwargs):
    encoding = kwargs.get('encoding', 'utf-8')
    sep = kwargs.get('sep', '\n')
    buf = []
    for filename in filenames:
        fspath = os.path.join(os.path.dirname(__file__), filename)
        with io.open(fspath, encoding=encoding) as f:
            buf.append(f.read())
    return sep.join(buf)


ver = '0.0.0'
version_file = os.path.join(os.path.dirname(__file__), 'rfw', '_version.py')
with open(version_file) as f:
    verLine = f.read().strip()
    vsRE = r"^__version__ = ['\"]([^'\"]*)['\"]"
    mo = re.search(vsRE, verLine, re.M)
    if mo:
        ver = mo.group(1)

setup(
    name="rfw",
    version=ver,
    author="SecurityKISS Ltd",
    author_email="open.source@securitykiss.com",
    description="Remote firewall as a web service. REST API for iptables.",
    license="MIT",
    keywords="rfw remote firewall iptables REST web service drop accept ban allow whitelist fail2ban",
    url="https://github.com/securitykiss-com/rfw",
    packages=['rfw'],
    scripts=['bin/rfw'],
    data_files=[('/etc/logrotate.d', ['config/logrotate.d/rfw']), ('/etc/init.d', ['config/init.d/rfw']),
                ('/etc/rfw', ['config/rfw.conf', 'config/white.list']),
                ('/etc/rfw/deploy', ['config/deploy/rfwgen', 'config/deploy/README.rst']),
                ('/etc/rfw/ssl', ['config/ssl/PUT_SERVER_KEYS_HERE'])],
    long_description=read('README.rst', 'CHANGES.rst'),
    cmdclass={'install': post_install},
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
    ],
)
