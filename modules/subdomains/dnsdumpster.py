#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.helpers.crawler import WCrawler


class MethodDnsDumpster(object):

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
                'title'   : self.context.strings['methods']['dnsdumpster']['title']
            }
        )

        self.context.out(
            self.context.strings['methods']['dnsdumpster']['getting-token-xsrf']
        )

        # Use the crawler bot
        crawler = WCrawler()

        # json result
        result = None

        try:
            result = crawler.httpRequest(
                url='https://dnsdumpster.com/'
            )

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['dnsdumpster']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['dnsdumpster']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Find token XSRF
        matches = re.search(
            br'name=\'csrfmiddlewaretoken\'\s+value=\'(.+?)\'',
            result['response-content'],
            re.I | re.M
        )
        
        if(not matches):
            # No token found
            self.context.out(
                self.context.strings['methods']['robtex']['no-xsrf-token-found']
            )
            return

        # El token XSRF
        tokenXsrf = matches.group(1)

        self.context.out(
            self.context.strings['methods']['dnsdumpster']['getting-subdomains']
        )

        try:
            result = crawler.httpRequest(
                url='https://dnsdumpster.com/',
                postData={
                    'csrfmiddlewaretoken' : tokenXsrf,
                    'targetip'            : self.context.baseHostname
                }
            )

        except Exception as e:
            raise e
            self.context.out(
                self.context.strings['methods']['dnsdumpster']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            print(result)
            self.context.out(
                message=self.context.strings['methods']['dnsdumpster']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(self.context.baseHostname).encode() + br')<',
            result['response-content']
        )

        if(len(matches) == 0):
            self.context.out(
                self.context.strings['methods']['dnsdumpster']['empty']
            )
            return

        # Process all matches
        for item in matches:

            # Add full hostname
            self.context.addHostName(
                hostname=item.decode(),
                messageFormat=self.context.strings['methods']['dnsdumpster']['item-found']
            )
