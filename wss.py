#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import signal
import traceback
import pytz
import ntpath
import socket
import re
import inspect
from   glob        import glob
from   os.path     import dirname, basename, abspath
from   datetime    import datetime
from   anytree     import Node, RenderTree
from   collections import deque

from modules.axfr               import MethodAxfr
from modules.dnsqueries         import MethodDnsQueries
from modules.virustotal         import MethodVirusTotal
from modules.robtex             import MethodRobtex
from modules.crtsh              import MethodCrtSh
from modules.certificatedetails import MethodCertificateDetails
from modules.google             import MethodGoogle
from modules.bing               import MethodBing
from modules.dnsdumpster        import MethodDnsDumpster
from modules.dictionary         import MethodDictionary


# Controller class
class Controller(object):

    def __init__(self):

        # Current language file (change this for other languages)
        # Try load json file
        with open('resources/strings.es.json', 'r') as fileHandler:
            self.strings = json.load(fileHandler)

        # Python 3 is required
        if sys.version_info < (3, 0):
            print(self.strings['errors']['bad-python-version'])
            exit(1)

        # The main header
        self.out(self.strings['header'])
        
        # Have a hostname as argument?
        if(len(sys.argv) < 2):
            self.out(
                message=self.strings['usage'],
                parseDict={
                    'scriptname': str(sys.argv[0])
                }
            )
            return

        # Call all methods
        self.processAllMethods()

        # Have subdomains?
        if(len(self.subdomains) == 0):
            self.out(self.strings['result']['empty'])
            return

        # Get all ip address
        self.getAllIpAddress()

        # Show the results
        self.showResulsts()


    def processAllMethods(self):

        # Order of methods
        self.methods = [
            {
                'title' : self.strings['methods']['axfr']['title'],
                'class' : MethodAxfr(self)
            },
            {
                'title' : self.strings['methods']['dns-queries']['title'],
                'class' : MethodDnsQueries(self)
            },
            {
                'title' : self.strings['methods']['virus-total']['title'],
                'class' : MethodVirusTotal(self)
            },
            {
                'title' : self.strings['methods']['robtex']['title'],
                'class' : MethodRobtex(self)
            },
            {
                'title' : self.strings['methods']['crt-sh']['title'],
                'class' : MethodCrtSh(self)
            },
            {
                'title' : self.strings['methods']['certificate-details']['title'],
                'class' : MethodCertificateDetails(self)
            },
            {
                'title' : self.strings['methods']['google']['title'],
                'class' : MethodGoogle(self)
            },
            {
                'title' : self.strings['methods']['bing']['title'],
                'class' : MethodBing(self)
            },
            {
                'title' : self.strings['methods']['dnsdumpster']['title'],
                'class' : MethodDnsDumpster(self)
            },
            {
                'title' : self.strings['methods']['dictionary-words']['title'],
                'class' : MethodDictionary(self, 'resources/dict-subdomains.txt')
            },
            {
                'title' : self.strings['methods']['dictionary-4']['title'],
                'class' : MethodDictionary(self, 'resources/dict-brute-4.txt')
            }
        ]

        # Have metods?
        if(len(self.methods) == 0):
            self.out(self.strings['errors']['empty-methods'])
            return

        self.progress = {
            'methods' : {
                'current' : 0,
                'total'   : len(self.methods)
            },
            'method' : {
                'found'   : 0
            }
        }

        # Stack of subdomains found
        self.subdomains      = []
        self.domain = str(sys.argv[1])

        # Can continue to next method?
        self.canContinue = True

        # Start methods
        for method in self.methods:

            # Starter value of subdomains found in the current method
            self.progress['method']['found'] = 0

            # Increase the method count
            self.progress['methods']['current'] += 1

            # Print the current progress of the methods
            self.out(
                message=self.strings['method-begin'],
                parseDict={
                    'current' : self.progress['methods']['current'],
                    'total'   : self.progress['methods']['total'],
                    'title'   : method['title']
                }
            )

            # Find subdomains in the current method
            method['class'].find(hostnameBase=self.domain)

            # Free memory and call the destructor
            # For free local storage like as MethodVirusTotal.hostnames
            method['class'] = None

            # Line spacing to bottom of method
            self.out('')

            if(not self.canContinue):
                break


    def getAllIpAddress(self):

        # Sorted and uniques results
        self.subdomains = sorted(set(self.subdomains))
        
        # Stack of all hostnames and address
        self.hosts = {}

        self.out(self.strings['get-ip-address']['title'])

        # Process each subdomain in order
        for hostname in self.subdomains:

            # ip = self.strings['errors']['unknown_ip_address_key']

            # Find the ip address
            self.out(
                message=self.strings['get-ip-address']['item-progress'],
                parseDict={
                    'hostname': hostname
                },
                end=''
            )

            ipAddress = None
            try:
                ipAddress = str(socket.gethostbyname(hostname))
                self.out(ipAddress)

            except Exception as e:
                ipAddress = 'Unknown'
                self.out(self.strings['get-ip-address']['unknown'])

            # Make the stack with new ip address
            if(not ipAddress in self.hosts):
                self.hosts[ipAddress] = []

            # Add host to ip address stack
            if(not hostname in self.hosts[ipAddress]):
                # TODO: Other data? ports, etc. Example: .append({ 'host': item_host, 'ports': { '80': ..., '443': ... } })
                self.hosts[ipAddress].append(hostname)
        
        # Line spacing to bottom of function
        self.out('')


    def showResulsts(self):

        # Show the results
        dt = datetime.utcnow().replace(tzinfo=pytz.utc).strftime('[%Y-%m-%d %H_%M_%S]')
        saveLogPath = 'subdomains_' + self.domain + '_' + dt + '.log'

        # Print the header message
        self.out(self.strings['result']['result-all-title'])

        # Tree structure
        nodeRoot = Node(
            self.strings['result']['node']['root'].replace(
                '{count}',
                str(sum(len(v) for v in list(self.hosts.values())))
            )
        )

        # Order by ip address
        self.hosts = { k: v for k, v in sorted(self.hosts.items()) }
        for ipAddress, records in self.hosts.items():
            nodeIp = Node(ipAddress, parent=nodeRoot)
            # self.hosts[ipAddress] = dict_reorder(records)
            for host in records:
                Node(host, parent=nodeIp)

        # Make the tree
        message = []
        for pre, fill, node in RenderTree(nodeRoot):
            message.append(
                self.strings['result']['node']['item-printed'].replace(
                    '{item}', pre + node.name
                )
            )

        # Show the tree
        self.out('\n'.join(message))
        
        # Save the tree
        fileHandler = open(saveLogPath, 'w') 
        fileHandler.write('\n'.join(message))
        fileHandler.close()
        
        # Free the memory
        message = None

        # Newline as separator
        self.out('')

        # Show the bottom result
        self.out(
            message=self.strings['result']['finish'],
            parseDict={
                'path': saveLogPath
            }
        )


    def out(self, message, parseDict=None, end='\n'):

        # Multiline?
        if(isinstance(message, list)):
            message = '\n'.join(message)

        # Multivalue?
        if(
            (parseDict) and
            isinstance(parseDict, dict)
        ):
            for key, value in parseDict.items():
                message = str(message).replace('{' + str(key) + '}', str(value))

        # Print the message
        print(str(message), end=end)


    def addHostName(self, hostname, messageFormat=None):

        # Add the hostname
        if(not hostname in self.subdomains):
            self.subdomains.append(hostname)

        # Quiet mode?
        if(messageFormat is None):
            return

        # Print the progress
        self.out(
            message=messageFormat,
            parseDict={
                'hostname': hostname
            }
        )


if __name__ == '__main__':
    try:
        controllerCls = Controller()

    except (KeyboardInterrupt, SystemExit):
        exit(0)
