#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
from modules.crawler import WCrawler


class MethodGoogle:

    def __init__(self, context):

        # The main context
        self.context = context
        
        # Unique only
        self.hostnames = []

        # API Key id
        self.googleApiKey = 'AIzaSyD_NlD2Lz1OgewxdZasjCquLo6AWYdeJz0'

        # Search id
        self.googleCx = '010763716184496466486:fscqb-8v6rs'


    def find(self, hostnameBase):

        if(not self.googleApiKey.strip()):
            self.context.out(
                self.context.strings['methods']['google']['no-api-key']
            )
            return

        # Find on first page
        self.paginate(hostnameBase)


    def paginate(self, hostnameBase, pageNumber=1):

        searchContext = {
            'max-pages'   : 15,
            'max-result'  : 10,
            'start-index' : 1,
            'query'       : 'site:' + hostnameBase
        }
        
        if(self.hostnames):
            # Does not process known subdomains
            searchContext['query'] += ' -site:' + ' -site:'.join(self.hostnames)

        # Current start item number
        searchContext['start-index'] = (
            ((pageNumber - 1) * searchContext['max-result']) + 1
        )

        # Header message for pagination
        self.context.out(
            self.context.strings['methods']['google']['pagination']
        )

        # Use the crawler bot
        crawler = WCrawler()

        # json result
        result = None

        try:
            result = crawler.httpRequest(
                'https://www.googleapis.com/customsearch/v1?' +
                'cx='     + crawler.urlencode(self.googleCx) +
                '&key='   + crawler.urlencode(self.googleApiKey) +
                '&q='     + crawler.urlencode(searchContext['query']) +
                '&start=' + str(searchContext['start-index']) + 
                '&filter=1&safe=off&num=' + str(searchContext['max-result'])
            )

            # Free memory (no navigation context)
            crawler.clearContext()

        except Exception as e:
            self.context.out(
                self.context.strings['methods']['google']['no-connect']
            )
            return

        if(result['status-code'] in [403, 400]):
            # No more resulsts
            self.context.out(
                self.context.strings['methods']['google']['no-more-results']
            )
            return

        # The http response is success?
        if(result['status-code'] != 200):
            self.context.out(
                message=self.context.strings['methods']['google']['wrong-status-http'],
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
                self.context.strings['methods']['google']['corrupt-response']
            )
            return

        if(
            (not 'items' in result) or
            (len(result['items']) == 0)
        ):
            self.context.out(
                self.context.strings['methods']['google']['no-more-results']
            )
            return

        # Process each result
        for item in result['items']:
            
            # Is a valid subdomain?
            if(not item['displayLink'].endswith('.' + hostnameBase)):
                continue
            
            if(not item['displayLink'] in self.hostnames):

                # For unique resulsts
                self.hostnames.append(item['displayLink'])

                # Add full hostname
                self.context.addHostName(
                    hostname=item['displayLink'],
                    messageFormat=self.context.strings['methods']['google']['item-found']
                )

                # Return to first page again
                pageNumber = 0

        # Limit of pages
        if(pageNumber >= searchContext['max-pages']):
            self.context.out(
                self.context.strings['methods']['google']['no-more-results']
            )
            return

        # Next page
        self.paginate(
            hostnameBase=hostnameBase,
            pageNumber=pageNumber + 1
        )