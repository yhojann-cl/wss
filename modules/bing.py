#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from modules.crawler import WCrawler


class MethodBing:

    def __init__(self, context):

        # The main context
        self.context = context

        # Unique only
        self.hostnames = []


    def find(self, hostnameBase):

        # Find on first page
        self.paginate(hostnameBase)


    def paginate(self, hostnameBase, pageNumber=1):

        searchContext = {
            'max-pages'   : 15,
            'max-result'  : 10,
            'start-index' : 1,
            'query'       : 'domain:' + hostnameBase
        }

        if(self.hostnames):
            # Does not process known subdomains
            searchContext['query'] += ' -domain:' + ' -domain:'.join(self.hostnames)

        # Current start item number
        searchContext['start-index'] = (
            ((pageNumber - 1) * searchContext['max-result']) + 1
        )

        # Header message for pagination
        self.context.out(
            message=self.context.strings['methods']['bing']['pagination']
        )

        # Use the crawler bot
        crawler = WCrawler()

        # json result
        result = None

        try:
            result = crawler.httpRequest(
                'https://www.bing.com/search?' +
                '&q='     + crawler.urlencode(searchContext['query']) +
                '&first=' + str(searchContext['start-index'])
            )

            # Free memory (no navigation context)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['bing']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['bing']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        # Example: <cite>https://foo<strong>domain.com</strong>
        matches = re.findall(
            br'>([\w\.\-\_\$]+?\.' + re.escape(hostnameBase).encode() + br')',
            result['response-content'].replace(
                b'<strong>' + hostnameBase.encode(),
                b'.' + hostnameBase.encode()
            )
        )

        if(len(matches) == 0):
            self.context.out(
                self.context.strings['methods']['bing']['no-more-results']
            )
            return

        # Process all matches
        for item in matches:

            # Unique resulsts
            if(item.decode() in self.hostnames):
                continue

            # Add to unique stack
            self.hostnames.append(item.decode())

            # Add full hostname
            self.context.addHostName(
                hostname=item.decode(),
                messageFormat=self.context.strings['methods']['bing']['item-found']
            )

        # Can continue to next page?
        if(not b'sw_next' in result['response-content']):
            self.context.out(
                self.context.strings['methods']['bing']['no-more-results']
            )
            return
            
        # Limit of pages
        if(pageNumber >= searchContext['max-pages']):
            self.context.out(
                self.context.strings['methods']['bing']['no-more-results']
            )
            return

        # Next page
        self.paginate(
            hostnameBase=hostnameBase,
            pageNumber=pageNumber + 1
        )