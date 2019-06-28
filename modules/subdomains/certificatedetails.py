#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import re
from modules.helpers.crawler import WCrawler


class MethodCertificateDetails:

    def __init__(self, context):

        # The main context
        self.context = context
        
        # Unique only
        self.hostnames = []


    def find(self):

        # Header message
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['certificate-details']['title']
            }
        )

        # Use the crawler bot
        crawler = WCrawler()

        # json result
        result = None

        try:
            result = crawler.httpRequest(
                url='https://certificatedetails.com/api/list/' + crawler.urlencode(self.context.baseHostname)
            )

            # Free memory (no navigation context)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['certificate-details']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['certificate-details']['wrong-status-http'],
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
                self.context.strings['methods']['certificate-details']['corrupt-response']
            )
            return

        if(
            (not isinstance(result, list)) or
            (len(result) == 0)
        ):
            self.context.out(
                self.context.strings['methods']['certificate-details']['empty']
            )
            return

        # Process each hostname
        for item in result:

            # Drop root wildcards
            if(item['CommonName'] == ('*.' + self.context.baseHostname)):
                continue

            # Valid subdomain?
            if(not item['CommonName'].endswith('.' + self.context.baseHostname)):
                continue

            if(item['CommonName'].startswith('*.')):
                item['CommonName'] = item['CommonName'][2:]

            if(not item['CommonName'] in self.hostnames):

                # For unique results
                self.hostnames.append(item['CommonName'])

                # Add full hostname
                self.context.addHostName(
                    hostname=item['CommonName'],
                    messageFormat=self.context.strings['methods']['crt-sh']['item-found']
                )

        # Header message to process all links
        self.context.out(
            self.context.strings['methods']['certificate-details']['find-links']
        )

        # Current link id
        linkId = 0

        # Process each link
        # Caution: Same hostname contain one o more certificates
        for item in result:

            linkId += 1

            self.findInLink(
                url='https://certificatedetails.com' + item['Link'],
                linkId=linkId,
                totalLinks=len(result)
            )


    def findInLink(self, url, linkId, totalLinks):

        self.context.out(
            message=self.context.strings['methods']['certificate-details']['find-link'],
            parseDict={
                'link-id'     : linkId,
                'total-links' : totalLinks
            }
        )
        
        # Use the crawler bot
        crawler = WCrawler()

        # json result
        result = None

        try:
            result = crawler.httpRequest(url=url)

            # Free memory (no navigation context)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['certificate-details']['no-connect']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['certificate-details']['wrong-status-http'],
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
            # Nothing
            return

        # Process all matches
        for item in matches:

            if(
                (not item.decode() in self.hostnames) and

                # Valid subdomain?
                (item.decode().endswith('.' + self.context.baseHostname))
            ):
            
                # For unique results
                self.hostnames.append(item.decode())

                # Add full hostname
                self.context.addHostName(
                    hostname=item.decode(),
                    messageFormat=self.context.strings['methods']['certificate-details']['item-found']
                )
