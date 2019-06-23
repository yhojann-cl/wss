#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import dns.resolver
import dns.zone
import dns.exception
import dns.rdatatype
import dns.rdata


class MethodAxfr(object):

    def __init__(self, context):

        # The main context
        self.context = context

        # Default timeout for DNS TCP/Socket
        socket.setdefaulttimeout = 0.50


    def find(self, hostnameBase):

        # Get NS Servers
        self.context.out(
            self.context.strings['methods']['axfr']['getting-ns-servers']
        )

        fqdn = hostnameBase
        if(hostnameBase.count('.') > 1):
            fqdn = '.'.join(hostnameBase.split('.')[:-1])

        nameServers = []
        try:
            ans = dns.resolver.query(fqdn, 'NS', tcp=True)
            nameServers = [a.to_text().strip('.') for a in ans]
            nameServers = set(nameServers)    # Uniques
            nameServers = sorted(nameServers) # Sorted

        except Exception as e:
            pass

        except dns.exception.DNSException as e:
            pass

        if(len(nameServers) == 0):
            self.context.out(
                self.context.strings['methods']['axfr']['unable-get-ns-servers']
            )
            return False

        # Process each record
        for nameServer in nameServers:
            if(
                (nameServer == hostnameBase) or
                (not nameServer.endswith(hostnameBase))
            ):
                continue

            # New subdomain found (hidden/quiet mode)
            self.context.addHostName(hostname=nameServer)

        # Begin message
        self.context.out(
            self.context.strings['methods']['axfr']['making-axfr-queries']
        )

        # Process each NS Server
        for nameServer in nameServers:

            # Print the progress
            self.context.out(
                message=self.context.strings['methods']['axfr']['ns-progress'],
                parseDict={
                    'nameserver': nameServer
                },
                end=''
            )

            axfr = None
            try:
                # Make the query (timeout in seconds)
                axfr = dns.query.xfr(
                    where=nameServer,
                    zone=hostnameBase,
                    lifetime=5.0
                )

            except Exception as e:
                # Unable make the AXFR query
                self.context.out(
                    self.context.strings['methods']['axfr']['ns-not-vulnerable']
                )
                continue

            zone = None
            try:
                # Get flushed data
                zone = dns.zone.from_xfr(axfr)
            
            except Exception as e:
                # Unable get the records
                self.context.out(
                    self.context.strings['methods']['axfr']['ns-not-vulnerable']
                )
                continue

            if zone is None:
                # Empty records
                self.context.out(
                    self.context.strings['methods']['axfr']['ns-not-vulnerable']
                )
                continue

            # Print ns vulnerable status
            self.context.out(
                    message=self.context.strings['methods']['axfr']['ns-vulnerable'],
                    parseDict={
                        'count': len(zone.nodes.items())
                    }
                )
            
            self.context.out(
                self.context.strings['methods']['axfr']['getting-items']
            )

            # Process each node
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets

                # Process each record
                for rdataset in rdatasets:

                    if(str(name) == '@'):
                        continue

                    # Add the full hostname found
                    # itemType = dns.rdatatype.to_text(rdataset.rdtype)
                    self.context.addHostName(
                        hostname=str(name) + '.' + hostnameBase,
                        messageFormat=self.context.strings['methods']['axfr']['item-found']
                    )
            
            # Finish all
            self.context.canContinue = False
            break
