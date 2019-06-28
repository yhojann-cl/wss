#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.crawler import WCrawler


class MethodRobtex:

    def __init__(self, context):

        # The main context
        self.context = context


    def find(self):

        # Header message
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['robtex']['title']
            }
        )

        # Use the crawler bot
        crawler = WCrawler()
        crawler.defaultTimeout = 30

        # html result
        result = None

        try:
            result = crawler.httpRequest(
                url='https://www.robtex.com/dns-lookup/' + crawler.urlencode(self.context.baseHostname)
            )

            # Free memory (no navigation context)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['robtex']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['robtex']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Remove strong tags
        # foo.<b>domain.com</b>
        result['response-content'] = result['response-content'].replace(
            b'<b>', b''
        ).replace(
            b'</b>', b''
        )

        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(self.context.baseHostname).encode() + br')<',
            result['response-content']
        )

        if(len(matches) == 0):
            self.context.out(
                self.context.strings['methods']['robtex']['empty']
            )
            return

        # Process all matches
        for item in matches:

            # Add full hostname
            self.context.addHostName(
                hostname=item.decode(),
                messageFormat=self.context.strings['methods']['robtex']['item-found']
            )
