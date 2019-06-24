#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import threading
import dns.resolver
import dns.reversename
import dns.zone
import dns.exception
import dns.rdatatype
import dns.rdata
import socket
import re
import hashlib
from random import random


class MethodDictionary(object):

    def __init__(self, context, dictionaryPath):

        # The main context
        self.context = context

        # The fork context
        self.dictionary = {
            'threads'             : [],
            'max-threads'         : 100,
            'file-handler'        : None,
            'file-path'           : dictionaryPath,
            'nameservers'         : [
                # The slower (less threads), the more effective.
                
                # Without custom ns (empty array) is more fast, 
                # 500 to 1000 threads max, but they can prohibit easier access.

                # APNIC  NS (200 threads max but errors occur more frequently)
                # '1.1.1.1', '1.0.0.1',

                # Google NS (100 threads max but is more stable)
                '8.8.8.8', '8.8.4.4'
            ],
            'n-subdomains-in-file': 0,
            'current-line'        : 0,
            'retries'             : 0,
            'max-retries'         : 2,
            'hostname-base'       : None
        }

        # Default timeout for DNS TCP/Socket
        socket.setdefaulttimeout = 0.50
        

    def find(self, hostnameBase):

        # Main hostname base
        self.dictionary['hostname-base'] = hostnameBase

        if(self.haveWildcard()):
            self.context.out(
                self.context.strings['methods']['dictionary']['wildcard-detected']
            )
            return

        self.context.out(
            self.context.strings['methods']['dictionary']['counting-items']
        )

        # Count lines
        # Use different file handler
        f = open(self.dictionary['file-path'], 'r')
        while True:
            b = f.read(65536)
            if not b:
                f.close()
                break
            self.dictionary['n-subdomains-in-file'] += b.count('\n')

        if(self.dictionary['n-subdomains-in-file'] > 0):
            self.dictionary['n-subdomains-in-file'] += 1

        self.context.out(
            self.context.strings['methods']['dictionary']['total-items'],
            parseDict={
                'total-items': "{:,}".format(self.dictionary['n-subdomains-in-file'])
            }
        )

        # File handler of the dictionary
        self.dictionary['file-handler'] = open(self.dictionary['file-path'], 'r')

        self.context.out(
            self.context.strings['methods']['dictionary']['loading-threads']
        )

        # Make space for the buffer progress
        # https://invisible-island.net/xterm/ctlseqs/ctlseqs.html
        self.context.out(
            self.context.strings['methods']['dictionary']['progress-pre']
        )

        # Make threads
        while True:

            # current_thread += 1

            # Thread handler
            t = threading.Thread(target=self.threadCheck)

            # Prevent show errors on finish the main thread
            t.setDaemon(True)

            # append thread to stack
            self.dictionary['threads'].append(t)

            # Thread limit?
            if(len(self.dictionary['threads']) >= self.dictionary['max-threads']):
                break

        # Run all threads
        for t in self.dictionary['threads']:
            t.start()

        # Wait for threads
        for t in self.dictionary['threads']:
            if(t.is_alive()):
                t.join()

        # Clear space of the buffer rogress
        self.context.out(
            self.context.strings['methods']['dictionary']['progress-clear']
        )


    def haveWildcard(self):

        # Validate a wildcard as subdomain
        m = hashlib.md5()
        m.update((str(random()) + 'fake').encode('utf-8', 'ignore'))
        fakeSubdomain = '__' + m.hexdigest() + '__.' + self.dictionary['hostname-base']

        useWilcard = None

        try:
            resolv = dns.resolver.Resolver()
            if(self.dictionary['nameservers']):
                # Custom nameservers
                resolv.nameservers = self.dictionary['nameservers']
            useWilcard = resolv.query(
                fakeSubdomain,
                'A',
                tcp=True
            )
            
        except Exception as e:
            pass

        return useWilcard


    def threadCheck(self):

        while(True):

            subdomain = None

            try:
                # Try read the next line from dictionary
                subdomain = self.dictionary['file-handler'].readline().strip().lower()

                # Line count
                self.dictionary['current-line'] += 1

            except Exception as e:
                pass

            if(not subdomain):
                # No more lines
                break

            # The full hostname
            hostname = subdomain.strip() + '.' + self.dictionary['hostname-base']
            retries  = 0

            # Retries
            while(True):

                # Info progress
                self.context.out(
                    message=(
                        self.context.strings['methods']['dictionary']['progress-clear'] +
                        '\n'.join(self.context.strings['methods']['dictionary']['progress'])
                    ),
                    parseDict={
                        'hostname'      : hostname,
                        'current-line'  : "{:,}".format(self.dictionary['current-line']),
                        'total-lines'   : "{:,}".format(self.dictionary['n-subdomains-in-file']),
                        'percent-lines' : "{:,.2f}".format(((self.dictionary['current-line'] * 100) / self.dictionary['n-subdomains-in-file'])) + '%',
                        'total-threads' : self.dictionary['max-threads'],
                        'total-retries' : self.dictionary['retries']
                    },
                    end=''
                )

                # Check if have a ip address
                nsAnswer = None
                try:

                    resolv = dns.resolver.Resolver()
                    if(self.dictionary['nameservers']):
                        # Custom nameservers
                        resolv.nameservers = self.dictionary['nameservers']

                    nsAnswer = resolv.query(

                        # Full hostname to find
                        hostname,

                        # Record type
                        'A',

                        # TCP for better results
                        tcp=True
                    )

                    if(nsAnswer):

                        # For each response data of record
                        for rdata in nsAnswer:

                            # Get the ip address from current response record
                            ip = rdata.to_text().strip('"')

                            # The record have a valid ip address?
                            # ip = str(socket.gethostbyname(hostname)) Fail ns server
                            if(ip):

                                # Add full hostname
                                self.context.addHostName(
                                    hostname=hostname,
                                    messageFormat=(

                                        # Clear space of the buffer rogress
                                        self.context.strings['methods']['dictionary']['progress-clear'] +

                                        # Show the subdomain found
                                        self.context.strings['methods']['dictionary']['item-found'] +

                                        # Make space for the buffer progress
                                        self.context.strings['methods']['dictionary']['progress-pre']
                                    )
                                )

                                # Break for
                                break

                    # Break while
                    break

                except dns.resolver.NXDOMAIN:
                    # No such domain
                    break

                except dns.resolver.Timeout:
                    # Retry

                    # Update retries count for this hostname
                    retries += 1

                    # Update global retries counts
                    self.dictionary['retries'] += 1

                    # Limit of retries
                    if(retries > self.dictionary['max-retries']):
                        break

                except dns.exception.DNSException:
                    # Unknown exception
                    break

                except Exception as e:
                    # Unknown exception
                    break