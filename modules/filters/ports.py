#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
from ipaddress import IPv4Address, IPv4Network
from IPy import IP

from modules.helpers.crawler import WCrawler


class FilterPorts(object):

    def __init__(self, context):

        # The main context
        self.context = context

        # 10.0.0.0\8
        self.classA = IPv4Network(('10.0.0.0', '255.0.0.0'))

        # 172.16.0.0\12
        self.classB = IPv4Network(('172.16.0.0', '255.240.0.0'))

        # 192.168.0.0\16
        self.classC = IPv4Network(('192.168.0.0', '255.255.0.0'))

        self.hostnameContext = {
            'check-ports'        : [ ],
            'ports-found'        : { },
            'threads-handlers'   : [ ],
            'current-ip-address' : None
        }


    def filterAll(self):
        
        # Header message
        self.context.out(
            message=self.context.strings['filter-begin'],
            parseDict={
                'current' : self.context.progress['filters']['current'],
                'total'   : self.context.progress['filters']['total'],
                'title'   : self.context.strings['filters']['ports']['title']
            }
        )

        # For each ip address
        itemNumber = 0
        for ipAddress in self.context.results['ip-address']['items'].keys():

            itemNumber += 1

            if(ipAddress == 'unknown'):
                continue

            # Main structure for current ip address
            self.context.results['ip-address']['items'][ipAddress]['items']['ports'] = {
                'title' : self.context.strings['filters']['ports']['node-tree']['ports-title'],
                'items' : self.findPorts(ipAddress, itemNumber)
            }


    def findPorts(self, ipAddress, itemNumber):

        self.context.out(
            message=self.context.strings['filters']['ports']['find'],
            parseDict={
                'address': ipAddress,
                'current': itemNumber,
                'total'  : len(self.context.results['ip-address']['items'].keys())
            }
        )

        # Local range
        if(IP(ipAddress).iptype() in ['PRIVATE', 'LOOPBACK']):
            self.context.out(
                self.context.strings['filters']['ports']['skip']
            )
            return []

        # if(address in self.classA):
        #     pass

        # Hostname context (for multithreading)
        self.hostnameContext['check-ports']        = list(reversed(range(1, 65535)))
        self.hostnameContext['ports-found']        = { }
        self.hostnameContext['threads-handlers']   = [ ]
        self.hostnameContext['current-ip-address'] = ipAddress

        # 1024 Threads by default
        for threadNumber in range(1, 1024):

            # Thread handler
            t = threading.Thread(target=self.threadCheck)

            # Prevent show errors on finish the main thread
            t.setDaemon(True)

            # append thread to stack
            self.hostnameContext['threads-handlers'].append(t)

        # Run all threads
        for t in self.hostnameContext['threads-handlers']:
            t.start()

        # Wait for threads
        for t in self.hostnameContext['threads-handlers']:
            if(t.is_alive()):
                t.join()

        # Clear progress without padding
        self.context.out(
            message=self.context.strings['filters']['ports']['progress-clear'],
            end=''
        )

        # Sorted results by port number
        return { k: v for k, v in sorted(self.hostnameContext['ports-found'].items()) }


    def threadCheck(self):

        while(True):
        
            if(len(self.hostnameContext['check-ports']) == 0):
                # No more ports
                break

            # Get next port
            port = int(self.hostnameContext['check-ports'].pop())

            self.context.out(
                message=(
                    self.context.strings['filters']['ports']['progress-clear'] +
                    self.context.strings['filters']['ports']['progress']
                ),
                parseDict={
                    'port': port
                },
                end=''
            )

            isOpen = False

            try:
                socketHandler = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socketHandler.settimeout(7) # In seconds
                socketHandler.connect((
                    self.hostnameContext['current-ip-address'],
                    port
                ))
                socketHandler.shutdown(1)
                socketHandler.close()

                isOpen = True

            except Exception as e:
                pass

            if(isOpen):

                # Rewrite current progress using the result
                self.context.out(
                    message=(
                        self.context.strings['filters']['ports']['progress-clear'] +
                        self.context.strings['filters']['ports']['found'] + '\n' +
                        self.context.strings['filters']['ports']['progress-wait']
                    ),
                    parseDict={
                        'port'  : port
                    },
                    end=''
                )

                # Append port to list of results
                # As object: To easy process in other filters
                self.hostnameContext['ports-found'][port] = None