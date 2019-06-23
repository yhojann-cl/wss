#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.exception
import re
import socket


class MethodDnsQueries:

    def __init__(self, context):

        # The main context
        self.context = context

        # Default timeout for DNS TCP/Socket
        socket.setdefaulttimeout = 0.50


    def find(self, hostnameBase):

        # Have subdomains?
        found = False

        # For each record type to found
        for recordType in ['MX', 'TXT', 'SPF', 'NS']:

            self.context.out(
                message=self.context.strings['methods']['dns-queries']['title-query-type'],
                parseDict={
                    'type': recordType
                }
            )

            answer = None
            try:
                answer = dns.resolver.query(hostnameBase, recordType, tcp=True)

            except Exception as e:
                # Unable make the DNS query
                continue

            for rdata in answer:

                # Hostnames found in current response (unique)
                hostnames = []

                # Plain record
                plainRecord = rdata.to_text().strip('"')

                # Find all possible full hostname in the plain response
                matches = re.findall(
                    r'([a-zA-Z0-9\.\-\_\$]+?\.' + re.escape(hostnameBase) + r')',
                    plainRecord
                )

                if(len(matches) == 0):
                    # No matches found
                    continue

                for item in matches:
                    if(
                        # Is not same base hostname
                        (item != hostnameBase) and

                        # Is a valid subdomain
                        (item.endswith(hostnameBase)) and

                        # Unique record for this response
                        (not item in hostnames)
                    ):
                        # Ok, have subdomains
                        found = True

                        # Append to response stack for
                        # unique report for each response.
                        hostnames.append(item)

                        # Add to main stack and print the result
                        self.context.addHostName(
                            hostname=item,
                            messageFormat=self.context.strings['methods']['dns-queries']['item-found']
                        )
        
        if(not found):
            self.context.out(
                self.context.strings['methods']['dns-queries']['no-items-found']
            )
