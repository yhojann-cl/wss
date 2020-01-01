#!/usr/bin/env python3
# # -*- coding: utf-8 -*-

import sys

from resources.util.constants import constants
from resources.util.i18n import get_locale, lang_from_path
from resources.util.helpers import Helper
from resources.util.logging import Logging, LogLevel


class Wss(object):

    langbuf = None
    lang = None
    langpath = None

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
        lang = args.get('--lang')
        if lang is None:
            #Trying found by short flag
            lang = args.get('-l')
            if lang is None:
                langpath = h.formatter('resources/lang/{}.json',
                                       [get_locale()])
                return langpath
            else:
                langpath = h.formatter('resources/lang/{}.json', [lang])
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
        flag = None
        args = {}
        for (x, y) in enumerate(sys.argv[1:]):
            f = y[:1]
            fe = f * 2
            #if pair-number case, as flag
            if ((x % 2) == 0):
                if ((f == '-') or (fe == '--')):
                    args[y] = None
                    flag = y
            #otherwise, as flag param
            else:
                if ((f == '-') or (fe == '--')):
                    args[y] = None
                    flag = y
                else:
                    args[flag] = y
        return args

    def parse_args(self, args):
        for (flag) in args:
            if ((flag == '-s') or (flag == '--server')):
                pass
                
if __name__ == '__main__':
    try:
        wss = Wss()
    except (KeyboardInterrupt, SystemExit):
        print(' ')
        exit(0)
