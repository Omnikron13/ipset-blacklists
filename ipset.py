import re
import subprocess

from config import conf

# Adds a new hash:net set, failing silently if it already exists
def create_hash_net(name, extra=[]):
    bin = conf['ipset']['binary']
    subprocess.call([bin, 'create', name, 'hash:net', '-exist'] + extra)

# Adds a new bitmap:port set, failing silently if it already exists
def create_bitmap_port(name):
    bin = conf['ipset']['binary']
    subprocess.call([bin, 'create', name, 'bitmap:port', 'range', '0-65535', '-exist'])

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
