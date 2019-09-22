import re
import subprocess

from config import conf


# This regex only really provides a rough matching capability, and will match
# on numbers >255 & subnets >32, but is probably faster than being more anal.
#CIDR_REGEX = '^(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?$'

# This alternative is very strict about what it considers 'correct', but is somewhat slower.
CIDR_REGEX = '^(?:(\d|[1-9]\d|1\d{2}|2[0-4]\d+|25[0-5])\.){3}(\d|[1-9]\d|1\d{2}|2[0-4]\d+|25[0-5])(?:\/([0-9]|[1-2]\d|3[0-2]))?$'


# Adds a new hash:net set, failing silently if it already exists
def create_hash_net(name, extra=''):
    bin = conf['ipset']['binary']
    subprocess.call(f'{bin} create {name} hash:net -exist {extra}'.split())

# Adds a new bitmap:port set, failing silently if it already exists
def create_bitmap_port(name):
    bin = conf['ipset']['binary']
    subprocess.call(f'{bin} create {name} bitmap:port range 0-65535 -exist'.split())

# Add to a specified set
def add(ipset, data):
    bin = conf['ipset']['binary']
    subprocess.call([bin, 'add', ipset, data, '-exist'])


# Remove from a specified set
def delete(ipset, data):
    bin = conf['ipset']['binary']
    subprocess.call([bin, 'del', ipset, data, '-exist'])


# Returns a list of ports stored in the given set
def get_ports(name):
    # TODO: error if set specified is not type bitmap:port?
    bin = conf['ipset']['binary']
    result = subprocess.run([bin, 'list', name], stdout=subprocess.PIPE)
    decoded = result.stdout.decode()
    return [i for i in decoded.splitlines() if re.match('^\d+$', i) is not None]


# Return (python) set containing the IPs from specified (ipset) set
def get_ips(name):
    # TODO: error if set specified is not type hash:net (or similar?)
    create_hash_net(name)
    bin = conf['ipset']['binary']
    result = subprocess.run([bin, 'list', name], stdout=subprocess.PIPE)
    items = set()
    for line in result.stdout.splitlines():
        m = re.match(CIDR_REGEX, line.decode())
        if m is None:
            continue
        items.add(m.string)
    return items
