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

import base64
import logging
import os
import socket
import ssl
from socketserver import BaseServer

from http.server import HTTPServer, BaseHTTPRequestHandler

# Follow the logging convention: - Modules intended as reusable libraries have names 'lib.<modulename>' what allows
# to configure single parent 'lib' logger for all libraries in the consuming application - Add NullHandler (since
# Python 2.7) to prevent error message if no other handlers present. The consuming app may add other handlers to
# 'lib' logger or its children.
log = logging.getLogger('lib.{}'.format(__name__))
log.addHandler(logging.NullHandler())


class PlainServer(HTTPServer):
    def __init__(self, server_address, HandlerClass):
        BaseServer.__init__(self, server_address, HandlerClass)
        self.socket = socket.socket(self.address_family, self.socket_type)
        self.server_bind()
        self.server_activate()


class SSLServer(HTTPServer):
    def __init__(self, server_address, HandlerClass, certfile, keyfile):
        if not os.path.isfile(certfile):
            raise IOError("SSLServer could not locate certfile {}".format(certfile))
        if not os.path.isfile(keyfile):
            raise IOError("SSLServer could not locate keyfile {}".format(keyfile))
        BaseServer.__init__(self, server_address, HandlerClass)
        self.socket = ssl.wrap_socket(
            socket.socket(self.address_family, self.socket_type),
            keyfile=keyfile,
            certfile=certfile
        )
        self.server_bind()
        self.server_activate()


class CommonRequestHandler(BaseHTTPRequestHandler):

    # override to include access logs in main log file
    def log_message(self, log_format, *args):
        log.info("%s - - [%s] %s" %
                 (self.client_address[0],
                  self.log_date_time_string(),
                  log_format % args))

    def http_resp(self, code, content):
        content = str(content)
        self.send_response(code)
        self.send_header("Content-Length", str(len(content) + 2))
        self.end_headers()
        self.wfile.write(b"{content}\r\n")
        return


def auth_basic(realm, text):
    """Callback decorator to require HTTP basic authentication"""

    def decorator(func):
        def wrapper(this, *a, **ka):
            parse_result = func(this, *a, **ka)
            # TODO can we call this.func(*a, **ka) ? No, because func is not defined on this. The obj.func() call
            #  syntax takes func as literal function (or rather method) name, while func(obj) call first
            #  evaluates func which is a variable containing a function.

            if not parse_result:  # don't process authentication if other error
                return False
            # After func was called (parse_request), this.headers should be populated. this.headers are of type
            # mimetools.Message parse_auth to return tuple (user, password)
            creds = this.parse_auth(this.headers.get("Authorization", ""))
            if not creds or not this.credentials_check(*creds):
                # log attempts with wrong credentials
                if creds:
                    ip = this.client_address[0]
                    log.warning("Authentication attempt with wrong credentials from {}".format(ip))
                this.send_response(401)
                this.send_header('WWW-Authenticate', 'Basic realm="{}"'.format(realm))
                this.send_header('Connection', 'close')
                this.end_headers()
                return False
            return True

        return wrapper

    return decorator


class BasicAuthRequestHandler(CommonRequestHandler):
    """HTTP request handler with Basic Authentication. It automatically sends back HTTP response code 401 if no valid
    Autorization header present in the request. """

    # To be overridden with actual credentials check
    def credentials_check(self, user, password):
        return False

    def parse_auth(self, header):
        """Parse rfc2617 HTTP authentication header string (basic) and return (user,pass) tuple or None"""
        try:
            method, data = header.split(None, 1)
            if method.lower() == 'basic':
                # it may fail with ValueError if the b64 string is corrupted
                user, pwd = base64.b64decode(data).split(b':', 1)
                return user, pwd
        except (KeyError, ValueError):
            return None

    # Overriding parse_request() to decorate it with basic authentication BTW. parse_request is a deceptive name.
    # Returns True or False. On failure it sends back the response to the client. Also there is one gotcha about
    # decorator: auth_basic is a decorator defined as a method, it is treated neither as an instance method,
    # class method nor static method. See http://stackoverflow.com/questions/11740626/can-a-class-method-be-a-decorator

    @auth_basic(realm='private', text='Access denied')
    def parse_request(self):
        return BaseHTTPRequestHandler.parse_request(self)
