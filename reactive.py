#!/bin/python

import os
import re
import subprocess
import toml
from urllib.request import urlopen

import ipset
from config import conf
from util import diff


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
    prefix = conf['reactive']['ipset_prefix']
    name = conf['reactive']['ipset_ips']
    timeout = str(conf['reactive']['timeout'])
    ipset.create_hash_net(name, ['timeout', timeout])
    ipset.create_bitmap_port('%s.%s' % (prefix, 'TCP'))
    ipset.create_bitmap_port('%s.%s' % (prefix, 'UDP'))


# Remove old ports and add new ports to the set
def update_ports(protocol, db):
    name = '%s.%s' % (conf['reactive']['ipset_prefix'], protocol.upper())
    ports = ipset.get_ports(name)
    blacklist = [i['port'] for i in db[protocol][0:conf['reactive']['count']]]
    # Remove old ports
    for p in diff(ports, blacklist):
        print("Removing port %s" % p)
        ipset.delete(name, p)
    # Add new ports
    for p in diff(blacklist, ports):
        print("Adding port %s" % p)
        ipset.add(name, p)
    # Removing whitelisted ports
    for p in conf['reactive'][f'whitelist_{protocol}']:
        print(f'Removing whitelisted port {p}')
        ipset.delete(name, str(p))


# Returns a rule/argument string for adding/checking/removing rules that check port
# blacklists and add matching IPs to the reactive blacklist
def iptables_rule_match_ports(protocol, cmd = 'A'):
    chain = conf['iptables']['chain']
    ipset_ports = '%s.%s' % (conf['reactive']['ipset_prefix'], protocol.upper())
    ipset_ips = conf['reactive']['ipset_ips']
    return f'-{cmd} {chain} -p {protocol} -m set --match-set {ipset_ports} dst -j SET --add-set {ipset_ips} src'


# Returns a rule/argument string for blocking IPs which have triggered one of the
# port matching rules
def iptables_rule_block_matches(cmd = 'A'):
    chain = conf['iptables']['chain']
    ipset = conf['reactive']['ipset_ips']
    return f'-{cmd} {chain} -m set --match-set {ipset} src -j DROP'


# Checks if a rule is already attached to the iptables chain
def iptables_rule_exists(rule):
    bin = conf['iptables']['binary']
    rule = rule.replace('-A', '-C', 1)
    r = subprocess.call(
        [bin] + rule.split(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if r is 0:
        return True
    return False


# Add a new rule to the iptables chain, failing silently if it already exists
def iptables_add_rule(rule):
    if iptables_rule_exists(rule):
        return
    bin = conf['iptables']['binary']
    subprocess.call(
        [bin] + rule.split(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# Add the iptables rules that actually match & block reactively
def iptables_add_rules():
    iptables_add_rule(iptables_rule_block_matches())
    iptables_add_rule(iptables_rule_match_ports('tcp'))
    iptables_add_rule(iptables_rule_match_ports('udp'))


# Function which creates the firewall. This is the only function that really
# needs calling, from an end-user perspective.
def setup():
    # Download and process data on common ports
    db = process_ports_db(conf['reactive']['nmap-services_url'])

    # Create and populate the ipsets
    create_ipsets()
    update_ports('tcp', db)
    update_ports('udp', db)

    # Create the iptables rules to match & block
    iptables_add_rules()
# Global to cache the downloaded & processed ports db
db = process_ports_db(conf['reactive']['nmap-services_url'])
