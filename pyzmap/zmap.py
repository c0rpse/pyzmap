#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
zmap.py - version and date, see below

Source code : https://github.com/c0rpse/pyzmap

Author :

* c0rpse - A pure man.

Licence: GPL v3 or any later version for pyzmap


This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.


**************
IMPORTANT NOTE
**************

The Zmap Security Scanner used by pyzmap is distributed
under it's own licence that you can find at https://www.zmap.io/

Any redistribution of pyzmap along with the Zmap Security Scanner
must conform to the Zmap Security Scanner licence

"""

__author__ = 'c0rpse (wdhgxc@gmail.com)'
__version__ = '0.1.1'
__last_modification__ = '2017.05.13'


import re
import sys
import subprocess


try:
    from multiprocessing import Process
except ImportError:
    # For pre 2.6 releases
    from threading import Thread as Process

############################################################################


class PortScanner(object):
    """
    PortScanner class allows to use zmap from python

    """

    def __init__(self, zmap_search_path=('zmap', '/usr/bin/zmap', '/usr/local/bin/zmap', '/sw/bin/zmap', '/opt/local/bin/zmap')):

        """
        Initialize PortScanner module

        * detects zmap on the system and zmap version
        * may raise PortScannerError exception if zmap is not found in the path

        :param zmap_search_path: tupple of string where to search for zmap executable. Change this if you want to use a specific version of zmap.
        :returns: nothing
        """
        self._nmap_path = ''  # zmap path
        self._scan_result = {}
        self._nmap_version_number = 0  # zmap version number
        self._nmap_subversion_number = 0  # zmap subversion number
        self._nmap_last_output = ''  # last full ascii zmap output
        is_zmap_found = False  # true if we have found zmap

        self.__process = None

        # regex used to detect zmap
        version_regex = re.compile(r'zmap ([0-9]*?\.){2}[0-9]*')

        # launch 'zmap -V'
        for zmap_path in zmap_search_path:
            try:
                if sys.platform.startswith('freebsd') \
                        or sys.platform.startswith('linux') \
                        or sys.platform.startswith('darwin'):
                    p = subprocess.Popen([zmap_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE,
                                         close_fds=True)
                else:
                    p = subprocess.Popen([zmap_path, '-V'],
                                         bufsize=10000,
                                         stdout=subprocess.PIPE)

            except OSError:
                pass
            else:
                self._zmap_path = zmap_path  # save path
                break
        else:
            raise PortScannerError(
                'zmap program was not found in path. PATH is : {0}'.format(
                    os.getenv('PATH')
                )
            )


class PortScannerError(Exception):
    """
    Exception error class for PortScanner class

    """
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

    def __repr__(self):
        return 'PortScannerError exception {0}'.format(self.value)


