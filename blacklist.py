#!/bin/python

import re
import subprocess
import toml
from urllib.request import urlopen

CONFIG_FILE = 'config.toml'
CIDR_REGEX = '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$'


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
        m = re.match(CIDR_REGEX, line.decode(charset))
        if m is None:
            continue
        items.add(m.string)
    return items


# Adds a new set, failing silently if it already exists
def create_ipset(name):
    subprocess.call(['/bin/ipset', 'create', name, 'hash:net', '-exist'])


# Return (python) set containing the IPs from specified (ipset) set
def get_ipset(name):
    create_ipset(name)
    result = subprocess.run(['/bin/ipset', 'list', name], stdout=subprocess.PIPE)
    items = set()
    for line in result.stdout.splitlines():
        m = re.match(CIDR_REGEX, line.decode('utf-8'))
        if m is None:
            continue
        items.add(m.string)
    return items


# Update an ipset to match contents of given blacklist
def set_ipset(ipsetname, blacklist):
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


# Return set of items in a which are not in b
def diff(a, b):
    return {i for i in a if i not in b}


# Complement to the diff() function above
def intersect(a, b):
    return {i for i in a if i in a and i in b}


# Iterate ipsets dictionary and update ipsets based on the latest version of source lists.
def update_ipsets(ipsets):
    for k, v in ipsets.items():
        blacklist = download_list(v)
        # TODO: decide how to handle where config is loaded form, and when it is loaded
        prefix = toml.load(CONFIG_FILE)['ipset']['prefix']
        set_ipset(f'{prefix}.{k}', blacklist)


