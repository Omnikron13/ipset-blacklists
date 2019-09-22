#!/bin/python

import os
import re
import subprocess
import toml
from urllib.request import urlopen

import ipset
from config import conf
from util import diff


# This regex only really provides a rough matching capability, and will match
# on numbers >255 & subnets >32, but is probably faster than being more anal.
#CIDR_REGEX = '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$'

# This alternative is very strict about what it considers 'correct', but is somewhat slower.
CIDR_REGEX = '^(?:(\d|[1-9]\d|1\d{2}|2[0-4]\d+|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d+|25[0-5])(?:\/([0-9]|[1-2]\d|3[0-2]))?$'


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


# Return (python) set containing the IPs from specified (ipset) set
def get_ipset(name):
    ipset.create_hash_net(name)
    bin = conf['ipset']['binary']
    result = subprocess.run([bin, 'list', name], stdout=subprocess.PIPE)
    items = set()
    for line in result.stdout.splitlines():
        m = re.match(CIDR_REGEX, line.decode())
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
    print("Adding IP: %s" % ip)
    bin = conf['ipset']['binary']
    subprocess.call([bin, 'add', ipset, ip, '-exist'])


# Remove an IP/CIDR from specified set
def remove_ip(ip, ipset):
    print("Removing IP: %s" % ip)
    bin = conf['ipset']['binary']
    subprocess.call([bin, 'del', ipset, ip, '-exist'])


# Iterate ipsets dictionary and update ipsets based on the latest version of source lists.
def update_ipsets(ipsets):
    for k, v in ipsets.items():
        blacklist = download_list(v)
        prefix = conf['ipset']['prefix']
        set_ipset(f'{prefix}.{k}', blacklist)
        iptables_rule_add(k)


# Add specified blacklist set to the iptables chain
def iptables_rule_add(name):
    # Don't duplicate the rule
    if(iptables_rule_exists(name)):
        return
    bin = conf['iptables']['binary']
    chain = conf['iptables']['chain']
    prefix = conf['ipset']['prefix']
    subprocess.call(
        [bin, '-A', chain, '-m', 'set', '--match-set', f'{prefix}.{name}', 'src', '-j', 'DROP'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Checks if an ipset blacklist is already attached to the iptables chain
def iptables_rule_exists(name):
    bin = conf['iptables']['binary']
    chain = conf['iptables']['chain']
    pre = conf['ipset']['prefix']
    r = subprocess.call(
        [bin, '-C', chain, '-m', 'set', '--match-set', f'{pre}.{name}', 'src', '-j', 'DROP'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if r is 0:
        return True
    return False

