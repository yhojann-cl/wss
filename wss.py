#!/usr/bin/env python3
# # -*- coding: utf-8 -*-

import sys

from resources.util.constants import constants
from resources.util.i18n import get_locale, lang_from_path
from resources.util.helpers import Helper
from resources.util.logging import Logging, LogLevel


def runtime():
    print("Runtime!")


class Wss(object):

    langbuf = None
    lang = None
    langpath = None
    CMDS = [{
        "title": "Server flag mode",
        "flags": ['s', 'server'],
        "runtime": runtime
    }, {
        "title": "Language flag mode",
        "flags": ['l', 'lang'],
        "runtime": runtime
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
        Logging.log(
            h.formatter(h.getlang(self.langbuf, 'cli', 'lang-setted'),
                        [langpath]), LogLevel.CLI)

    def build_args(self):
        cf = None
        args = {}
        for f in sys.argv[1:]:
            r = self.iva(f)
            if not r is None:
                args[r] = None
                cf = r
            else:
                args[cf] = f
                cf = None
        return args

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

    def parse_args(self, args):
        h = Helper()
        for flag in args.keys():
            cmd = self.found_command(flag)
            if not cmd is None:
                runtime = cmd.get('runtime')
                runtime()
            else:
                print('not found!', flag)

    def found_command(self, s):
        for command in self.CMDS:
            _list = command.get('flags')
            if s in _list:
                return command
        return None
            #return 
if __name__ == '__main__':
    try:
        wss = Wss()
    except (KeyboardInterrupt, SystemExit):
        print(' ')
        exit(0)
