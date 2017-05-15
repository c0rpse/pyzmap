#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/5/15 下午2:02
# @Author  : c0rpse
# @Site    : 
# @File    : utils.py
# @Software: PyCharm


def __get_last_online_version():
    """
    Gets last pyzmap published version

    WARNING : it does an http connection to http://xael.org/pages/python-nmap/python-nmap_CURRENT_VERSION.txt

    :returns: a string which indicate last published version (example :'0.4.3')

    """
    import http.client
    conn = http.client.HTTPConnection("xael.org")
    conn.request("GET", "/c0rpse/pyzmap/blob/master/pyzmap_CURRENT_VERSION.txt")
    online_version = bytes.decode(conn.getresponse().read()).strip()
    return online_version
