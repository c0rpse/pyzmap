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
import os
import shlex


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

    def __init__(self, zmap_search_path=('zmap', '/usr/bin/zmap', '/usr/local/bin/zmap', '/sw/bin/zmap',
                                         '/opt/local/bin/zmap')):

        """
        Initialize PortScanner module

        * detects zmap on the system and zmap version
        * may raise PortScannerError exception if zmap is not found in the path

        :param zmap_search_path: tupple of string where to search for zmap executable. Change this if you want to use a specific version of zmap.
        :returns: nothing
        """
        self._zmap_path = ''  # zmap path
        self._scan_result = {}
        self._zmap_version_number = 0  # zmap version number
        self._zmap_subversion_number = 0  # zmap subversion number
        self._zmap_last_output = ''  # last full ascii zmap output
        is_zmap_found = False  # true if we have found zmap
        self._output_fields = ['saddr', 'daddr', 'ipid', 'ttl', 'sport', 'dport', 'seqnum', 'acknum', 'window',
                               'classification', 'success', 'repeat', 'cooldown', 'timestamp-str', 'timestamp-ts',
                               'timestamp-us']
        self._output_filter = {'success': 1, 'repeat': 0}
        self._output_module = 'json'
        self.__process = None

        # regex used to detect zmap
        version_regex = re.compile(r'zmap (([0-9]*?\.){2}[0-9]*)')

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
        self._zmap_last_output = bytes.decode(p.communicate()[0])
        # 获取版本信息
        _zmap_version = self._zmap_last_output.strip(os.linesep)
        if version_regex.match(_zmap_version) is not None:
            is_zmap_found = True
            self._zmap_version_number = version_regex.findall(_zmap_version)[0][0]

        if not is_zmap_found:
            raise PortScannerError('zmap program was not found in path')
        return

    def scan(self, hosts='127.0.0.1', port=80, arguments='', output_path='zmap.json', sudo=False):
        """
        Scan given hosts

        May raise PortScannerError exception if zmap output was not xml

        Test existance of the following key to know
        if something went wrong : ['zmap']['scaninfo']['error']
        If not present, everything was ok.

        :param hosts: string for hosts as zmap use , such as '198.116.0.12' or '198.116.0.12/24 216.163.128.20/20'
        :param port: string for port as zmap use it , such as '22' or '3389'
        :param output_path: string for output save path
        :param arguments: string of arguments for zmap '-N -B -p'
        :param sudo: launch zmap with sudo if True

        :returns: scan_result as dictionnary
        """
        if sys.version_info[0] == 2:
            assert type(hosts) in (str, unicode), 'Wrong type for [hosts], should be a string [was {0}]'.format(
                type(hosts))
            assert type(port) in (
            int, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(type(port))
            assert type(arguments) in (str, unicode), 'Wrong type for [arguments], should be a string [was {0}]'.format(
                type(arguments))  # noqa
        else:
            assert type(hosts) is str, 'Wrong type for [hosts], should be a string [was {0}]'.format(
                type(hosts))
            assert type(port) in (str, type(None)), 'Wrong type for [ports], should be a string [was {0}]'.format(
                type(port))
            assert type(arguments) is str, 'Wrong type for [arguments], should be a string [was {0}]'.format(
                type(arguments))

        # for redirecting_output in ['-oX', '-oA']:
        #     assert redirecting_output not in arguments, 'Xml output can\'t be redirected from command line.\nYou can access it after a scan using:\nnmap.nm.get_nmap_last_output()'  # noqa

        hosts_args = shlex.split(hosts)
        comms_args = shlex.split(arguments)
        args = [self._zmap_path] + hosts_args + ['-p', str(port)] * (port is not None) + comms_args
        if '-o' not in comms_args:
            args += ['-o', output_path]
        if '-O' not in comms_args:
            args += ['-O', self._output_module]
        if '--output-fields' not in comms_args:
            args += ['--output-fields', ','.join(self._output_fields)]
        if '--output-filter' not in comms_args:
            args += ['--output-filter',
                     '"' + '&&'.join([k + '=' + str(self._output_filter[k]) for k in self._output_filter]) + '"']
        if sudo:
            args = ['sudo'] + args
        p = subprocess.Popen(args, bufsize=100000,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        # wait until finished
        # get output
        (self._zmap_last_output, zmap_err) = p.communicate()
        self._zmap_last_output = bytes.decode(self._zmap_last_output.encode())
        zmap_err = bytes.decode(zmap_err)

        zmap_err_keep_trace = []
        zmap_warn_keep_trace = []
        zmap_info_keep_trace = []
        if len(zmap_err) > 0:
            regex_warn = re.compile('^.*?\[WARN\].*', re.IGNORECASE)
            regex_info = re.compile('^.*?\[INFO\].*', re.IGNORECASE)
            for line in zmap_err.split(os.linesep):
                if len(line) > 0:
                    rgw = regex_warn.search(line)
                    if rgw is not None:
                        zmap_warn_keep_trace.append(line+os.linesep)
                    else:
                        rgi = regex_info.search(line)
                        if rgi is not None:
                            zmap_info_keep_trace.append(line + os.linesep)
                        else:
                            zmap_err_keep_trace.append(line + os.linesep)
        print self._zmap_last_output


    def zmap_version(self):
        """
        returns zmap version if detected (int version, int subversion)
        or (0, 0) if unknown
        :returns: (zmap_version_number, zmap_subversion_number)
        """
        return self._zmap_version_number, self._zmap_subversion_number

    def zmap_path(self):
        """
        returns zmap path if detected
        or '' if unknown
        :returns: string
        """
        return self._zmap_path

    def get_zmap_last_output(self):
        """
        Returns the last text output of zmap in raw text
        this may be used for debugging purpose

        :returns: string containing the last text output of zmap in raw text
        """
        return self._zmap_last_output




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


