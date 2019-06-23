#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from modules.crawler import WCrawler


class MethodVirusTotal:

    def __init__(self, context):

        # The main context
        self.context = context

        # Unique only
        self.hostnames = []


    def find(self, hostnameBase, nextUrl=None, pageId=1):

        self.context.out(
            message=self.context.strings['methods']['virus-total']['paginating'],
            parseDict={
                'number': pageId
            }
        )

        # Use the crawler bot
        crawler = WCrawler()

        # json result
        result = None

        try:
            if(nextUrl is None):
                result = crawler.httpRequest(
                    url='https://www.virustotal.com/ui/domains/' + crawler.urlencode(hostnameBase) + '/subdomains?limit=40'
                )
            else:
                result = crawler.httpRequest(nextUrl)

            # Free memory (no navigation context)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['virus-total']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['virus-total']['wrong-status-http'],
                parseDict={
                    'id': result['status-code']
                }
            )
            return

        try:
            # Convert the result into json object
            result = json.loads(result['response-content'])

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['virus-total']['corrupt-response']
            )
            return

        if(len(result['data']) == 0):
            self.context.out(self.context.strings['methods']['virus-total']['no-more'])
            return

        # Process all subdomains found
        for item in result['data']:

            # Unique results for this instance
            if(str(item['id']) in self.hostnames):
                continue

            # Add to current stack for unique results
            self.hostnames.append(str(item['id']))

            # Add full hostname
            self.context.addHostName(
                hostname=str(item['id']),
                messageFormat=self.context.strings['methods']['virus-total']['item-found']
            )

        # Need paginate?
        if(
            ('links' in result) and
            ('next' in result['links']) and
            (result['links'])
        ):
            self.find(
                hostnameBase=hostnameBase,
                nextUrl=str(result['links']['next']),
                pageId=(pageId + 1)
            )
