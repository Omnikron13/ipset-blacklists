#!/bin/python

import os
import re
import subprocess
import toml
from urllib.request import urlopen

import ipset
from config import conf
from util import diff


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
        m = re.match(ipset.CIDR_REGEX, line.decode(charset))
        if m is None:
            continue
        items.add(m.string)
    return items


# Update an ipset to match contents of given blacklist
def set_ipset(name, blacklist):
    ipset_ips = ipset.get_ips(name)
    for ip in diff(blacklist, ipset_ips):
        print(f'Adding IP: {ip}')
        ipset.add(name, ip)
    for ip in diff(ipset_ips, blacklist):
        print(f'Removing IP: {ip}')
        ipset.delete(name, ip)


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

