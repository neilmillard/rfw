#!/usr/bin/env python
#
# Copyrite (c) 2014 SecurityKISS Ltd (http://www.securitykiss.com)
#
# This file is part of rfw
#
# The MIT License (MIT)
#
# Yes, Mr patent attorney, you have nothing to do here. Find a decent job instead.
# Fight intellectual "property".
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import logging
from urllib.parse import parse_qsl, urlparse

import iptables
import iputil
import timeutil
from iptables import Rule

log = logging.getLogger("rfw.cmdparse")


def convert_iface(iface):
    """Convert iface string like 'any', 'eth', 'eth0' to iptables iface naming like *, eth+, eth0.
    """
    if iface == 'any':
        return '*'
    else:
        # append '+' quantifier to iface
        if not iface[-1].isdigit():
            iface += '+'
        return iface


class PathError(Exception):
    def __init__(self, path, msg=''):
        Exception.__init__(self, 'Incorrect path: {}. {}'.format(path, msg))


# return tuple:
# '/' -> tuple()
# '/list' -> ('list', '')
# '/list/input' -> ('list', 'input')
# '/drop/input/eth0/1.2.3.4' -> ('drop', Rule(...))

def parse_command_path(rule_path):
    # split url path into parts, lowercase, trim trailing slash, return tuple
    def path_parts(path):
        path = path.strip().lower()
        if len(path) < 1 or path[0] != '/':
            raise PathError(path)
        if path[-1] == '/':
            path = path[:-1]
        _p = list(map(str.strip, path.split('/')))
        _p = tuple(_p[1:])
        return _p

    parts = path_parts(rule_path)

    # for path = '/' return 'help' action
    if not parts:
        return 'help', None

    action = parts[0]

    if action.upper() in iptables.RULE_TARGETS:
        try:
            return action, build_rule(parts)
        except ValueError as e:
            raise PathError(rule_path, str(e))

    if action == 'list':

        if len(parts) == 1:
            return action, None
        elif len(parts) == 2:
            chain = parts[1].upper()
            if chain in iptables.RULE_CHAINS:
                return action, chain
            else:
                raise PathError(rule_path, 'Wrong chain name for list command')
        else:
            raise PathError(rule_path, 'Too many details for the list command')

    raise PathError(rule_path)


# From the path parts tuple build and return Rule for drop/accept/reject type of command
def build_rule(p):
    # There must be at least 4 parts like in /drop/input/eth0/1.2.3.4
    if len(p) < 2:
        raise ValueError('Not enough details to construct the rule')
    target = p[0].upper()
    if target not in iptables.RULE_TARGETS:
        raise ValueError('The action should be one of {}'.format(iptables.RULE_TARGETS))
    chain = p[1].upper()
    if target != 'CREATE' and chain not in iptables.RULE_CHAINS:
        raise ValueError('When not creating one, the chain should be one of {}'.format(iptables.RULE_CHAINS))

    interface1 = None
    ip1 = None
    port1 = None
    if len(p) > 2:
        interface1 = p[2]
        if len(interface1) > 16:
            raise ValueError('Interface name too long. Max 16 characters')
        interface1 = convert_iface(interface1)

        # Extract an endpoint
        ip1, port1 = iputil.extract_endpoint(p[3])

        if not ip1 or (port1 is not None and not port1):
            raise ValueError('Incorrect IP endpoint')

    mask1 = None
    interface2 = None
    ip2 = None
    port2 = None
    mask2 = None
    extra = ''
    protocol = 'all'
    if len(p) > 4:
        i = 4
        # optionally the netmask like: /drop/input/eth0/1.2.3.4/24
        if p[i].isdigit():
            if iputil.validate_mask_limit(p[i]):
                mask1 = p[i]
                i = i + 1
            else:
                raise ValueError('Netmask must be in range from 9 to 32')
        if len(p) > i:
            # iface2 for forward chain /drop/forward/eth0/1.2.3.4/eth1
            interface2 = p[i]
            i = i + 1
            if len(interface2) > 16:
                raise ValueError('Interface name too long. Max 16 characters')
            interface2 = convert_iface(interface2)
            if len(p) > i:
                ip2, port2 = iputil.extract_endpoint(p[i])
                i = i + 1
                if not ip2 or (port2 is not None and not port2):
                    raise ValueError('Incorrect IP endpoint or netmask')
                if len(p) > i:
                    # now it must be the correct netmask if something was given after IP
                    if iputil.validate_mask_limit(p[i]):
                        mask2 = p[i]
                    else:
                        raise ValueError('Incorrect netmask value')

    if chain in ['INPUT', 'OUTPUT']:
        if len(p) > 5:
            raise ValueError('Too many details for the {} chain'.format(chain))
        if len(p) > 4 and not mask1:
            raise ValueError('Incorrect netmask value')

    if chain in ['FORWARD']:
        if len(p) > 8:
            raise ValueError('Too many details for the {} chain'.format(chain))
        if len(p) > 7 and (not mask1 or not mask2):
            raise ValueError('Incorrect netmask value')
        if len(p) > 6 and not mask1 and not mask2:
            raise ValueError('Incorrect netmask value')

    if chain == 'INPUT':
        inp = interface1
        out = '*'
        source = ip1
        if mask1:
            source = '{}/{}'.format(source, mask1)
        destination = '0.0.0.0/0'
        if port1 is not None:
            if 'tcp' not in extra:
                extra = ('tcp ' + extra).strip()
            extra = extra + ' spt:' + port1
            protocol = 'tcp'
    elif chain == 'OUTPUT':
        inp = '*'
        out = interface1
        source = '0.0.0.0/0'
        destination = ip1
        if mask1:
            destination = '{}/{}'.format(destination, mask1)
        if port1 is not None:
            if 'tcp' not in extra:
                extra = ('tcp ' + extra).strip()
            extra = extra + ' dpt:' + port1
            protocol = 'tcp'
    elif chain == 'FORWARD':
        inp = interface1
        if interface2:
            out = interface2
        else:
            out = '*'
        source = ip1
        print('mask1: '.format(mask1))
        if mask1:
            source = '{}/{}'.format(ip1, mask1)
        destination = '0.0.0.0/0'
        if ip2:
            destination = ip2
        if mask2:
            destination = '{}/{}'.format(destination, mask2)
        if port1 is not None:
            if 'tcp' not in extra:
                extra = ('tcp ' + extra).strip()
            extra = extra + ' spt:' + port1
            protocol = 'tcp'
        if port2 is not None:
            if 'tcp' not in extra:
                extra = ('tcp ' + extra).strip()
            extra = extra + ' dpt:' + port2 if extra is not None else 'dpt:' + port2
            protocol = 'tcp'
    elif target == 'CREATE':
        inp = interface1
        out = interface1
        source = '0.0.0.0/0'
        destination = '0.0.0.0/0'
    else:
        inp = interface1
        if interface2:
            out = interface2
        else:
            out = '*'
        source = ip1
        destination = '0.0.0.0/0'
        if ip2:
            destination = ip2
        if mask1:
            source = '{}/{}'.format(source, mask1)
        if mask2:
            destination = '{}/{}'.format(destination, mask2)
        if port1 is not None:
            if 'tcp' not in extra:
                extra = ('tcp ' + extra).strip()
            extra = extra + ' spt:' + port1
            protocol = 'tcp'
        if port2 is not None:
            if 'tcp' not in extra:
                extra = ('tcp ' + extra).strip()
            extra = extra + ' dpt:' + port2 if extra is not None else 'dpt:' + port2
            protocol = 'tcp'
        if target == 'SNAT':
            extra = extra + ' to:' + destination
            destination = '0.0.0.0/0'  # Reset destination in order to prevent it from being appended

    return Rule({'target': target, 'chain': chain, 'prot': protocol, 'inp': inp, 'out': out, 'source': source,
                 'destination': destination, 'extra': extra})


def parse_command_query(query):
    params = dict(parse_qsl(query))
    ret = {}

    expire = params.get('expire')
    if expire:
        interval = timeutil.parse_interval(expire)
        if interval is None:
            raise ValueError('Incorrect expire parameter value')
        ret['expire'] = str(interval)

    wait = params.get('wait')
    if wait:
        wait = wait.lower()
        if wait == 'true':
            ret['wait'] = wait
        else:
            raise ValueError('Incorrect wait parameter value')

    modify = params.get('modify')
    if modify:
        modify = modify.lower()
        if modify in ['insert', 'delete']:
            ret['modify'] = modify
        else:
            raise ValueError('Incorrect modify parameter value')
    return ret


def parse_command(url):
    """
    return dict with command elements like:
    {'chain': 'input', 'iface1': 'eth', 'ip1': '11.22.33.44', 'expire': '3600'}
    chain == input implies that ip1 is a source address
    chain == output implies that ip1 is a destination address
    """
    # split input to path and query
    # path specifies the iptables Rule while query provides additional rfw parameters like expire or wait
    parsed = urlparse(url)
    path, query = parsed.path, parsed.query

    action, rule = parse_command_path(path)
    directives = parse_command_query(query)

    return action, rule, directives
