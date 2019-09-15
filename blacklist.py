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
    return items


# Add list (/set/etc.) to specified set
def add_ip_list(list, ipset):
    # TODO: add/remove differences?
    for ip in list:
        add_ip(ip, ipset)


# Update an ipset to match contents of given blacklist
def set_ipset(blacklist, ipsetname):
    ipset = get_ipset(ipsetname)
    for ip in diff(blacklist, ipset):
        add_ip(ip, ipsetname)
    for ip in diff(ipset, blacklist):
        remove_ip(ip, ipsetname)


# Add an IP/CIDR to specified set
def add_ip(ip, ipset):
    subprocess.call(['/bin/ipset', 'add', '-exist', ipset, ip])


# Remove an IP/CIDR from specified set
def remove_ip(ip, ipset):
    subprocess.call(['/bin/ipset', 'del', '-exist', ipset, ip])


# Return (python) set containing the IPs from specified (ipset) set
def get_ipset(ipset):
    result = subprocess.run(['/bin/ipset', 'list', ipset], stdout=subprocess.PIPE)
    items = set()
    for line in result.stdout.splitlines():
        m = re.match('(?:\d+\.){3}\d+(?:\\\d+)?', line.decode('utf-8'))
        if m is None:
            continue
        items.add(m.string)
    return items


# Return set of items in a which are not in b
def diff(a, b):
    return {i for i in a if i not in b}


