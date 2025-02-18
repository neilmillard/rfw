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
#

import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
from queue import Queue, PriorityQueue

import cmdparse
import config
import iptables
import iputil
import rfwconfig
import rfwthreads
from iptables import Iptables
from sslserver import SSLServer, PlainServer, BasicAuthRequestHandler, CommonRequestHandler

python_ver = sys.version_info
if python_ver[0] == 3 and python_ver[1] >= 7:
    pass
else:
    print("rfw requires python 3.7+")
    sys.exit(1)

log = logging.getLogger('rfw')


def print_err(msg):
    print(msg, file=sys.stderr)


def create_request_handlers(rfwconf, cmd_queue, expiry_queue):
    """Create RequestHandler type. This is a way to avoid global variables: a closure returning a class type that
  binds rfwconf and cmd_queue inside.
  """

    ver = '0.0.0'
    version_file = os.path.join(os.path.dirname(__file__), '_version.py')
    try:
        with open(version_file) as f:
            version_line = f.read().strip()
            version_re = r"^__version__ = ['\"]([^'\"]*)['\"]"
            mo = re.search(version_re, version_line, re.M)
            if mo:
                ver = mo.group(1)
            else:
                log.error('Could not find version string in {}'.format(version_file))
    except IOError as e:
        log.error('Could not read {}: {} {}'.format(version_file, e.strerror, e.filename))
    server_ver = 'SecurityKISS rfw/{}'.format(ver)

    def check_whitelist_conflict(ip, whitelist):
        if ip != '0.0.0.0/0' and iputil.ip_in_list(ip, whitelist):
            msg = 'Ignoring the request conflicting with the whitelist'
            log.warning(msg)
            raise Exception(msg)

    def process(handler, modify, url_path):
        # modify should be 'D' for Delete or 'I' for Insert understood as -D and -I iptables flags
        assert modify in ['D', 'I', 'L']

        try:
            action, rule, directives = cmdparse.parse_command(url_path)

            # log.debug('\nAction: {}\nRule: {}\nDirectives: {}'.format(action, rule, directives))

            if modify == 'L':
                if action == 'help':
                    resp = 'TODO usage'
                    return handler.http_resp(200, resp)
                elif action == 'list':
                    chain = rule
                    rules = Iptables.read_simple_rules(chain)
                    log.debug('List rfw rules: %s', rules)
                    list_of_dict = map(iptables.Rule._asdict, rules)
                    resp = json.dumps(list_of_dict)
                    return handler.http_resp(200, resp)
                elif rfwconf.is_non_restful():
                    mod = directives.get('modify')
                    if not mod:
                        raise Exception(
                            f'{action} Unrecognized command. Non-restful enabled, you need to provide modify parameter.')
                    if mod == 'insert':
                        modify = 'I'
                    elif mod == 'delete':
                        modify = 'D'
                    else:
                        raise Exception('Unrecognized command. Modify parameter can be "insert" or "delete".')
                else:
                    raise Exception('Unrecognized command. Non-restful disabled.')

            if modify in ['D', 'I'] and action.upper() in iptables.RULE_TARGETS:
                # eliminate ignored/whitelisted IP related commands early to prevent propagating them to expiry queue
                check_whitelist_conflict(rule.source, rfwconf.whitelist())
                check_whitelist_conflict(rule.destination, rfwconf.whitelist())
                ctup = (modify, rule, directives)
                log.debug('PUT to Cmd Queue. Tuple: {}'.format(ctup))
                cmd_queue.put_nowait(ctup)

                # Make these rules persistent on file
                import os.path
                if os.path.isfile("/etc/init.d/iptables-persistent"):
                    save_command = "/etc/init.d/iptables-persistent save"
                else:
                    raise Exception('No iptables-persistent command is installed. Please install it first!')
                if save_command is not None:
                    subprocess.call(save_command, shell=True)

                return handler.http_resp(200, ctup)
            else:
                raise Exception('Unrecognized command.')
        except Exception as err:
            msg = 'ERROR: {}'.format(e.message)
            # logging as error disabled - bad client request is not an error
            # log.exception(msg)
            log.info(msg)
            return handler.http_resp(400, msg)  # Bad Request

    class LocalRequestHandler(CommonRequestHandler):

        def go(self, modify, urlpath, remote_addr):
            process(self, modify, urlpath)

        def do_modify(self, modify):
            self.go(modify, self.path, self.client_address[0])

        def do_PUT(self):
            self.go('I', self.path, self.client_address[0])

        def do_DELETE(self):
            self.go('D', self.path, self.client_address[0])

        def do_GET(self):
            self.go('L', self.path, self.client_address[0])

    class OutwardRequestHandler(BasicAuthRequestHandler):

        def credentials_check(self, user, password):
            return user == rfwconf.auth_username() and password == rfwconf.auth_password()

        def go(self, modify, urlpath, remote_addr):
            # authenticate by checking if client IP is in the whitelist - normally requests from non-whitelisted IPs
            # should be blocked by firewall beforehand
            if not iputil.ip_in_list(remote_addr, rfwconf.whitelist()):
                log.error(
                    'Request from client IP: {} which is not authorized in the whitelist.'
                    ' It should have been blocked by firewall.'.format(
                        remote_addr))
                return self.http_resp(403, '')  # Forbidden

            process(self, modify, urlpath)

        def do_PUT(self):
            self.go('I', self.path, self.client_address[0])

        def do_DELETE(self):
            self.go('D', self.path, self.client_address[0])

        def do_GET(self):
            self.go('L', self.path, self.client_address[0])

    return LocalRequestHandler, OutwardRequestHandler


def create_args_parser():
    config_file = '/etc/rfw/rfw.conf'
    # TODO change default log level to INFO
    log_level = 'DEBUG'
    log_file = '/var/log/rfw.log'
    parser = argparse.ArgumentParser(description='rfw - Remote Firewall')
    parser.add_argument('-f', default=config_file, metavar='CONFIGFILE', dest='configfile',
                        help='rfw config file (default {})'.format(config_file))
    parser.add_argument('--loglevel', default=log_level, help='Log level (default {})'.format(log_level),
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('--logfile', default=log_file, help='Log file (default {})'.format(log_file))
    parser.add_argument('-v', help='Verbose console output. Sets DEBUG log level for stderr logger (default ERROR)',
                        action='store_true')
    return parser


def parse_args():
    parser = create_args_parser()
    args = parser.parse_args()
    args.loglevelnum = getattr(logging, args.loglevel)
    return args


def startup_sanity_check():
    """Check for most common errors to give informative message to the user
  """
    try:
        Iptables.verify_install()
        Iptables.verify_permission()
        Iptables.verify_original()
    except Exception as e:
        log.critical(e)
        sys.exit(1)


def __sigTERMhandler(signum, frame):
    log.debug("Caught signal {}. Exiting".format(signum))
    print_err('')
    stop()


def stop():
    logging.shutdown()
    sys.exit(1)


def rfw_init_rules(rfwconf):
    """Clean and insert the rfw init rules.
  The rules block all INPUT/OUTPUT traffic on rfw ssl port except for whitelisted IPs.
  Here are the rules that should be created assuming that that the only whitelisted IP is 127.0.0.1:
      Rule(chain='INPUT', num='1', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*',
           source='127.0.0.1', destination='0.0.0.0/0', extra='tcp dpt:7393')
      Rule(chain='INPUT', num='4', pkts='0', bytes='0', target='DROP', prot='tcp', opt='--', inp='*', out='*',
          source='0.0.0.0/0', destination='0.0.0.0/0', extra='tcp dpt:7393')
      Rule(chain='OUTPUT', num='1', pkts='0', bytes='0', target='ACCEPT', prot='tcp', opt='--', inp='*', out='*',
           source='0.0.0.0/0', destination='127.0.0.1', extra='tcp spt:7393')
      Rule(chain='OUTPUT', num='4', pkts='0', bytes='0', target='DROP', prot='tcp', opt='--', inp='*', out='*',
           source='0.0.0.0/0', destination='0.0.0.0/0', extra='tcp spt:7393')
  """
    if rfwconf.is_outward_server():
        rfw_port = rfwconf.outward_server_port()
    else:
        rfw_port = rfwconf.local_server_port()

    ipt = Iptables.load()

    ###
    log.info('Delete existing init rules')
    # find 'drop all packets to and from rfw port'
    drop_input = ipt.find({'target': ['DROP'], 'chain': ['INPUT'], 'prot': ['tcp'], 'extra': ['tcp dpt:' + rfw_port]})
    log.info(drop_input)
    log.info('Existing drop input to rfw port {} rules:\n{}'.format(rfw_port, '\n'.join(map(str, drop_input))))
    for r in drop_input:
        Iptables.exe_rule('D', r)
    drop_output = ipt.find({'target': ['DROP'], 'chain': ['OUTPUT'], 'prot': ['tcp'], 'extra': ['tcp spt:' + rfw_port]})
    log.info('Existing drop output to rfw port {} rules:\n{}'.format(rfw_port, '\n'.join(map(str, drop_output))))
    for r in drop_output:
        Iptables.exe_rule('D', r)

    ###
    log.info('Insert DROP rfw port init rules')
    Iptables.exe(['-I', 'INPUT', '-p', 'tcp', '--dport', rfw_port, '-j', 'DROP'])
    Iptables.exe(['-I', 'OUTPUT', '-p', 'tcp', '--sport', rfw_port, '-j', 'DROP'])

    ###
    log.info('Insert ACCEPT whitelist IP rfw port init rules')
    for ip in rfwconf.whitelist():
        try:
            Iptables.exe(['-D', 'INPUT', '-p', 'tcp', '--dport', rfw_port, '-s', ip, '-j', 'ACCEPT'])
            Iptables.exe(['-D', 'OUTPUT', '-p', 'tcp', '--sport', rfw_port, '-d', ip, '-j', 'ACCEPT'])
        except subprocess.CalledProcessError:
            pass  # ignore
        Iptables.exe(['-I', 'INPUT', '-p', 'tcp', '--dport', rfw_port, '-s', ip, '-j', 'ACCEPT'])
        Iptables.exe(['-I', 'OUTPUT', '-p', 'tcp', '--sport', rfw_port, '-d', ip, '-j', 'ACCEPT'])


def main():
    args = parse_args()
    try:
        config.set_logging(log, args.loglevelnum, args.logfile, args.v)
    except config.ConfigError as e:
        print_err(e.message)
        sys.exit(1)

    if args.v:
        log.info('Console logging in verbose mode')

    log.info("Logging to file: {}".format(args.logfile))
    log.info("File log level: {}".format(args.loglevel))

    try:
        rfwconf = rfwconfig.RfwConfig(args.configfile)
    except IOError as e:
        print_err(e.message)
        create_args_parser().print_usage()
        sys.exit(1)

    # Initialize Iptables with configured path to system iptables
    Iptables.ipt_path = rfwconf.iptables_path()
    startup_sanity_check()

    # Install signal handlers
    signal.signal(signal.SIGTERM, __sigTERMhandler)
    signal.signal(signal.SIGINT, __sigTERMhandler)
    # TODO we may also need to ignore signal.SIGHUP in daemon mode

    Iptables.loadChains()
    rules = Iptables.load().rules
    # TODO make logging more efficient by deferring arguments evaluation
    log.debug("===== rules =====\n{}".format("\n".join(map(str, rules))))

    log.info("Starting rfw server")
    log.info("Whitelisted IP addresses that will be ignored:")
    for a in rfwconf.whitelist():
        log.info('    {}'.format(a))

    # recreate rfw init rules related to rfw port
    rfw_init_rules(rfwconf)

    expiry_queue = PriorityQueue()
    cmd_queue = Queue()

    rfwthreads.CommandProcessor(cmd_queue,
                                rfwconf.whitelist(),
                                expiry_queue,
                                rfwconf.default_expire()).start()

    rfwthreads.ExpiryManager(cmd_queue, expiry_queue).start()

    # Passing HandlerClass to SSLServer is very limiting, seems like a bad design of BaseServer.
    # In order to pass extra info to RequestHandler without using global variable we have to wrap the class in closure.
    local_handler_class, outward_handler_class = create_request_handlers(rfwconf, cmd_queue, expiry_queue)
    if rfwconf.is_outward_server():
        server_address = (rfwconf.outward_server_ip(), int(rfwconf.outward_server_port()))
        httpd = SSLServer(
            server_address,
            outward_handler_class,
            rfwconf.outward_server_certfile(),
            rfwconf.outward_server_keyfile())
        rfwthreads.ServerRunner(httpd).start()

    if rfwconf.is_local_server():
        server_address = ('127.0.0.1', int(rfwconf.local_server_port()))
        httpd = PlainServer(
            server_address,
            local_handler_class)
        rfwthreads.ServerRunner(httpd).start()

    # wait forever
    time.sleep(1e9)


if __name__ == "__main__":
    main()
