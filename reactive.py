#!/bin/python

import os
import re
import subprocess
import toml
from urllib.request import urlopen

import ipset
from config import conf


# Regex to extract data from nmap-services file
REGEX = '^(?P<service>\S+)\s+(?P<port>\d+)\/(?P<protocol>\S+)\s+(?P<frequency>\S+)(?:\s+#\s+(?P<comment>.+))?$'


# Return a list of ports from nmap-services file
def download_ports_db(url):
    http = urlopen(url)
    # TODO: error handling
    charset = http.headers.get_content_charset()
    if charset is None:
        charset = 'utf-8' # Best guess
    items = list()
    for line in http:
        line = line.rstrip()
        m = re.match(REGEX, line.decode(charset))
        if m is None:
            continue
        items.append({
            'service'   : m.group('service'),
            'port'      : m.group('port'),
            'protocol'  : m.group('protocol'),
            'frequency' : m.group('frequency'),
            'comment'   : m.group('comment'),
        })
    return items


# Returns a dictionary of port entry lists keyed by protocol (tcp, udp, etc.)
def process_ports_db(url):
    db = download_ports_db(url)
    ports = dict()
    for p in {i['protocol'] for i in db}:
        ports[p] = [i for i in db if i['protocol'] == p]
        ports[p].sort(key = lambda i: i['frequency'], reverse = True)
    return ports


# Setup ipset sets used by the reactive firewall
def create_ipsets():
    name = conf['reactive']['ipset_ips']
    timeout = str(conf['reactive']['timeout'])
    ipset.create_hash_net(name, ['timeout', timeout])
    ipset.create_bitmap_port(conf['reactive']['ipset_ports_tcp'])
    ipset.create_bitmap_port(conf['reactive']['ipset_ports_udp'])

