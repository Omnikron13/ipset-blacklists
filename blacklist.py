#!/bin/python

import re
import subprocess
from urllib.request import urlopen

lists = {
    'CINSArmy' : 'http://cinsscore.com/list/ci-badguys.txt',
    'MyIP.ms'  : 'http://myip.ms/files/blacklist/csf/latest_blacklist.txt',
    'tyrael'   : 'http://tyrael.local/blacklist.txt',
    #'': '',
}


# Return a list of IPs/CIDR from a URL
def download_list(url):
    http = urlopen(url)
    # TODO: error handling
    charset = http.headers.get_content_charset()
    if charset is None:
        charset = 'utf-8' # Best guess
    items = set()
    for line in http:
        line = line.rstrip()
        m = re.match('(?:\d+\.){3}\d+(?:\\\d+)?', line.decode(charset))
        if m is None:
            continue
        items.add(m.string)
    items = list(items)
    # TODO: does this even need to be sorted?
    items.sort()
    return items


# Add list (/set/etc.) to specified set
def add_ip_list(list, ipset):
    # TODO: add/remove differences?
    for ip in list:
        add_ip(ip, ipset)


# Add an IP/CIDR to specified set
def add_ip(ip, ipset):
    subprocess.call(['/bin/ipset', 'add', '-exist', ipset, ip])


