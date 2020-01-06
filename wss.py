#!/usr/bin/env python3
# # -*- coding: utf-8 -*-

import sys
import os

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

if sys.version_info < (3, 0):
    Logging.log('Wrong Python version, exiting', LogLevel.DANGER)
    exit(-1)


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
    Logging.log(h.formatter(h.getlang(langbuf, 'running', None), [hostname]),
                LogLevel.CLI)
    print(' ')
    if param is not None:
        for p in param:
            if (p == '0'):
                render_tree(request_method(MethodAxfr(), 'AXFR'))
            elif (p == '1'):
                render_tree(request_method(MethodDnsQueries(), 'DNS Queries'))
            elif (p == '2'):
                render_tree(request_method(MethodVirusTotal(), 'VirusTotal'))
            elif (p == '3'):
                render_tree(request_method(MethodRobtex(), 'Robtex'))
            elif (p == '4'):
                render_tree(request_method(MethodCrtSh(), 'CRTSH'))
            elif (p == '5'):
                render_tree(
                    request_method(MethodCertificateDetails(),
                                   'CertificateDetails'))
            elif (p == '6'):
                render_tree(request_method(MethodGoogle(), 'Google CSE'))
            elif (p == '7'):
                render_tree(request_method(MethodBing(), 'Bing'))
            elif (p == '8'):
                render_tree(request_method(MethodDnsDumpster(),
                                           'DNS Dumpster'))


def run_filter(langbuf, param):
    h = Helper()
    if param is not None:
        res = []
        for p in param:
            if (p == '0'):
                if ((os.geteuid() == 0)
                        or (os.getenv('SUDO_USER') is not None)):
                    f = FilterRawPorts()
                    render_tree(request_filter(f.filter(hostname),
                                               'Raw Ports'))
                else:
                    Logging.log(h.getlang(langbuf, 'errors', 'root-required'),
                                LogLevel.DANGER)
            elif (p == '1'):
                f = FilterPorts()
                render_tree(request_filter(f.findPorts(hostname), 'Ports'))
            elif (p == '2'):
                f = FilterHttpServices()
                render_tree(
                    request_filter(f.findHttpServices(hostname),
                                   'Http Services'))


def define_host(langbuf, param):
    global hostname
    h = Helper()
    if h.hostname_validate(param) is None:
        Logging.log(h.getlang(langbuf, 'errors', 'invalid-hostname'),
                    LogLevel.DANGER)
        exit(-1)
    else:
        hostname = param


def request_filter(res, node_t='Untitle'):
    main_node = Node(node_t)
    if isinstance(res, dict):
        for k in res:
            v = res.get(k)
            if isinstance(v, list):
                render_list(k, v, main_node)
            elif isinstance(v, dict):
                render_dict(v, main_node)
            else:
                w = Node(v, parent=main_node)
    elif isinstance(res, list):
        for k in res:
            if isinstance(k, list):
                render_list(None, k, main_node)
            elif isinstance(k, dict):
                render_dict(k, main_node)
            else:
                w = Node(k, parent=main_node)
    else:
        n = Node(res, parent=main_node)

    return main_node


def request_method(clazz, node_t='Untitle'):
    main_node = Node(node_t)
    res = clazz.find(hostname)
    if isinstance(res, dict):
        for k in res:
            v = res.get(k)
            if isinstance(v, list):
                render_list(k, v, main_node)
            elif isinstance(v, dict):
                render_dict(v, main_node)
            else:
                w = Node(v, parent=main_node)
    elif isinstance(res, list):
        for k in res:
            if isinstance(k, list):
                render_list(None, k, main_node)
            elif isinstance(k, dict):
                render_dict(k, main_node)
            else:
                w = Node(k, parent=main_node)
    else:
        n = Node(res, parent=main_node)

    return main_node


def render_list(title, l, tree):
    if (len(l)):
        if title is not None:
            a = Node(title, parent=tree)
        for b in l:
            if a is not None:
                c = Node(b, parent=a)
            else:
                c = Node(b, parent=tree)


def render_dict(d, tree):
    h = Helper()
    t = ''
    for o in d:
        m = d.get(o)
        if isinstance(m, list):
            t += h.formatter('{}: {} ', [o, ', '.join(m)])
        elif isinstance(m, dict):
            for p in m:
                s = m.get(p)
                t += h.formatter('{}: {} ', [p, s])
        else:
            t += h.formatter('{}: {} ', [o, m])
    q = Node(t, parent=tree)


def render_tree(tree):
    h = Helper()
    for pre, fill, node in RenderTree(tree):
        Logging.log(h.formatter("{}{}", [pre, node.name]), LogLevel.CLI)


class Wss(object):

    lang = None
    langbuf = None
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
        Logging.log(h.ftext('WHK Subdomains Scanner', 'speed'), LogLevel.CLI)
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
