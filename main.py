#!/bin/python

import blacklist

blacklist.update_ipsets(blacklist.conf['blacklists'])
