#!/usr/bin/env python3
# # -*- coding: utf-8 -*-

import sys
import socket

from anytree import Node, RenderTree

from resources.util.constants import constants
from resources.util.i18n import get_locale, lang_from_path
from resources.util.helpers import Helper
from resources.util.logging import Logging, LogLevel

from modules.http.server import HttpServer
from modules.filters.ports import FilterPorts
from modules.filters.http import FilterHttpServices
from modules.filters.rawports import FilterRawPorts
from modules.subdomains.axfr import MethodAxfr
from modules.subdomains.dnsqueries import MethodDnsQueries
from modules.subdomains.virustotal import MethodVirusTotal
from modules.subdomains.robtex import MethodRobtex
from modules.subdomains.crtsh import MethodCrtSh
from modules.subdomains.certificatedetails import MethodCertificateDetails
from modules.subdomains.google import MethodGoogle
from modules.subdomains.bing import MethodBing
from modules.subdomains.dnsdumpster import MethodDnsDumpster
from modules.subdomains.dictionary import MethodDictionary

hostname = None


def show_help(langbuf, param):
    h = Helper()
    Logging.log(h.getlang(langbuf, 'usage', None), LogLevel.CLI)


def run_server(langbuf, param):
    h = Helper()
    c = param.split(':')
    ip = '127.0.0.1'
    port = 3000
    debug = 'on'
    if len(c):
        for v in c:
            if h.ip_validate(v) is not None:
                ip = v
            elif h.port_validate(v) is not None:
                port = v
            else:
                if v in ['on', 'off']:
                    debug = v
    http = HttpServer(ip, port, debug)
    http.start()


def run_method(langbuf, param):
    h = Helper()
    Logging.log(h.getlang(langbuf, 'running', None),
                            LogLevel.CLI)
    if param is not None:
        for p in param:
            if (p == '0'):
                axfr = MethodAxfr()
                res = axfr.find(hostname)
                #Output
                AXFR_node = Node('AXFR')
                NS_node = Node('nameservers', parent=AXFR_node)
                DOMAIN_node = Node('subdomains', parent=AXFR_node)
                ns = res.get('ns', [])
                dn = res.get('domains', [])
                for n in ns:
                    node = Node(n, parent=NS_node)
                for d in dn:
                    node = Node(d, parent=DOMAIN_node)

                for pre, fill, node in RenderTree(AXFR_node):
                    Logging.log(h.formatter("{}{}", [pre, node.name]),
                                LogLevel.CLI)

            elif (p == '1'):
                dnsq = MethodDnsQueries()
                res = dnsq.find(hostname)
                #Output
                DNSQ_node = Node('DNS Queries')
                for r in res:
                    node = Node(h.formatter('{} // {}', [
                        r.get('subdomain', '<n/a>'),
                        r.get('recordType', '<n/a>')
                    ]),
                                parent=DNSQ_node)
                for pre, fill, node in RenderTree(DNSQ_node):
                    Logging.log(h.formatter("{}{}", [pre, node.name]),
                                LogLevel.CLI)
            elif (p == '2'):
                virustotal = MethodVirusTotal()
                res = virustotal.find(hostname)
                #Output
                VIRUSTOTAL_node = Node('VirusTotal')
                for v in res:
                    node = Node(v, parent=VIRUSTOTAL_node)
                for pre, fill, node in RenderTree(VIRUSTOTAL_node):
                    Logging.log(h.formatter("{}{}", [pre, node.name]),
                                LogLevel.CLI)
            elif (p == '3'):
                robtex = MethodRobtex()
                res = robtex.find(hostname)
                #Output
                ROBTEX_node = Node('RobTex')
                for r in res:
                    node = Node(r, parent=ROBTEX_node)
                for pre, fill, node in RenderTree(ROBTEX_node):
                    Logging.log(h.formatter("{}{}", [pre, node.name]),
                                LogLevel.CLI)
            elif (p == '4'):
                crtsh = MethodCrtSh()
                res = crtsh.find(hostname)
                #Output
                CRTSH_node = Node('CRTSH')
                for c in res:
                    node = Node(c, parent=CRTSH_node)
                for pre, fill, node in RenderTree(CRTSH_node):
                    Logging.log(h.formatter("{}{}", [pre, node.name]),
                                LogLevel.CLI)


def run_filter(langbuf, param):
    print(param)


def define_host(langbuf, param):
    global hostname
    h = Helper()
    if h.hostname_validate(param) is None:
        Logging.log(h.getlang(langbuf, 'errors', 'invalid-hostname'),
                    LogLevel.DANGER)
        exit(-1)
    else:
        hostname = param


class Wss(object):

    langbuf = None
    lang = None
    langpath = None
    CMDS = [{
        "flags": ['h', 'help'],
        "runtime": show_help
    }, {
        "flags": ['host'],
        "runtime": define_host
    }, {
        "flags": ['a', 'api'],
        "runtime": run_server
    }, {
        "flags": ['m', 'methods'],
        "runtime": run_method
    }, {
        "flags": ['f', 'filters'],
        "runtime": run_filter
    }]

    def __init__(self):

        #Helper instance
        h = Helper()
        #Print banner
        Logging.log(h.ftext('WHK Subdomains Scanner'), LogLevel.CLI)
        #Parse arguments from cli
        args = self.build_args()
        argc = len(args)
        #Check if arguments was passed
        if not argc > 0:
            Logging.log(
                '- No CLI arguments found, try --help command for more info',
                LogLevel.DANGER)
            exit(-1)

        self.load_lang(self.define_lang(args))
        self.parse_args(args)

    #Define path for language to load
    def define_lang(self, args):
        h = Helper()
        #Trying found by long flag
        lang = args.get('lang')
        if lang is None:
            #Trying found by short flag
            lang = args.get('l')
            if lang is None:
                langpath = h.formatter('resources/lang/{}.json',
                                       [get_locale()])
                return langpath
            else:
                langpath = h.formatter('resources/lang/{}.json',
                                       [lang.lower()])
                return langpath
        else:
            langpath = h.formatter('resources/lang/{}.json', [lang.lower()])
            return langpath

    #Load language
    def load_lang(self, langpath):
        h = Helper()

        if not h.langexists(langpath):
            Logging.log('Can\'t define language to show, exiting...',
                        LogLevel.DANGER)
            exit(-1)
        else:
            self.langbuf = lang_from_path(langpath)
            if not isinstance(self.langbuf, dict):
                Logging.log('- Error loading language file', LogLevel.DANGER)
                exit(-1)

        Logging.log(
            h.formatter(h.getlang(self.langbuf, 'header', None),
                        [h.version(), h.gettime()]), LogLevel.CLI)

    #build args cli by sys.argv[]
    def build_args(self):
        cf = None
        args = {}
        for (g, f) in enumerate(sys.argv[1:]):
            if ((g % 2) == 0):
                r = self.iva(f)
                if r is not None:
                    args[r] = None
                    cf = r
                else:
                    if cf is not None:
                        args[cf] = f
                        cf = None
            else:
                r = self.iva(f)
                if r is not None:
                    args[r] = None
                    cf = r
                else:
                    if cf is not None:
                        args[cf] = f
                        cf = None
        return args

    #check if a is a valid argument
    def iva(self, a):
        i = a[:2]
        r = None
        if (i == '--'):
            r = a[2:]
        else:
            i = a[:1]
            if (i == '-'):
                r = a[1:]
        return r

    #check commands and lauch it
    def parse_args(self, args):
        h = Helper()
        for flag in args.keys():
            cmd = self.found_command(flag)
            if not cmd is None:
                runtime = cmd.get('runtime')
                runtime(self.langbuf, args[flag])

    #found a define command
    def found_command(self, s):
        for command in self.CMDS:
            _list = command.get('flags')
            if s in _list:
                return command
        return None


if __name__ == '__main__':
    try:
        wss = Wss()
    except (KeyboardInterrupt, SystemExit):
        print(' ')
        exit(0)
