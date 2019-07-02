#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import argparse
import pytz
import socket
from   datetime         import datetime
from   anytree          import Node, RenderTree
from   anytree.importer import DictImporter

# Subdomains finders
from modules.subdomains.axfr               import MethodAxfr
from modules.subdomains.dnsqueries         import MethodDnsQueries
from modules.subdomains.virustotal         import MethodVirusTotal
from modules.subdomains.robtex             import MethodRobtex
from modules.subdomains.crtsh              import MethodCrtSh
from modules.subdomains.certificatedetails import MethodCertificateDetails
from modules.subdomains.google             import MethodGoogle
from modules.subdomains.bing               import MethodBing
from modules.subdomains.dnsdumpster        import MethodDnsDumpster
from modules.subdomains.dictionary         import MethodDictionary

# Filters
from modules.filters.ports                 import FilterPorts
from modules.filters.http                  import FilterHttpServices


# Controller class
class Controller(object):

    def __init__(self):

        # Current language file (change this for other languages)
        # Try load json file
        with open('resources/strings/en.json', 'r') as fileHandler:
            self.strings = json.load(fileHandler)

        # Python 3 is required
        if sys.version_info < (3, 0):
            print(self.strings['errors']['bad-python-version'])
            exit(1)

        self.version = {
            'major'   : 2,
            'minor'   : 4,
            'patch'   : 3,
            'release' : 'beta'
        }

        # Main domain to find
        self.baseHostname = None

        # Dictionary of results
        # Format: 
        # {
        #     "ip-address": {
        #         "items": {
        #             "x.x.x.x": {
        #                 "items": {
        #                     "hostnames": {
        #                         "items": {
        #                             "www.example.com": null
        #                         },
        #                         "title": "Hostnames"
        #                     },
        #                     "ports": {
        #                         "items": [
        #                             80
        #                         ],
        #                         "title": "Ports"
        #                     }
        #                 },
        #                 "title": "x.x.x.x"
        #             },
        #             "unknown": {
        #                 "items": {
        #                     "hostnames": {
        #                         "items": {
        #                             "foo.example.com": null,
        #                             "bar.example.com": null
        #                         },
        #                         "title": "Hostnames"
        #                     }
        #                 },
        #                 "title": "Unknown IP address"
        #             }
        #         },
        #         "title": "3 hosts were found"
        #     }
        # }
        # You can add a custom values into tree using same structure.
        self.results = {
            'ip-address': {
                'title': self.parseString(
                    message=self.strings['result']['node-tree']['root'],
                    parseDict={
                        'count': 0
                    }
                ),
                'items': { }
            }
        }

        # Order of methods
        self.methods = [ ]

        # Order of filters
        self.filters = [ ]

        # Progress
        self.progress = {
            'methods' : {
                'current' : 0,
                'total'   : 0
            },
            'filters': {
                'current' : 0,
                'total'   : 0
            },
            'total-hostnames' : 0
        }

        # The main header
        self.out(
            message=self.strings['header'],
            parseDict={
                'version': (
                    str(self.version['major']) + '.' +
                    str(self.version['minor']) + '.' +
                    str(self.version['patch']) + '-' +
                    str(self.version['release'])
                )
            }
        )
        
        # Get arguments from CLI
        argparseHandler = argparse.ArgumentParser(
            add_help=False
        )

        argparseHandler.add_argument(
            '-h',
            '--help',
            dest='help',
            action='store_true'
        )

        argparseHandler.add_argument(
            '--host',
            dest='hostname',
            nargs='?'
        )

        argparseHandler.add_argument(
            '-m',
            '--methods',
            dest='methods',
            nargs='?'
        )

        argparseHandler.add_argument(
            '-f',
            '--filters',
            dest='filters',
            nargs='?'
        )

        # Parse all arguments
        arguments, unknownArguments = argparseHandler.parse_known_args(
            sys.argv[1:]
        )

        # Hostname is required
        if(not arguments.hostname):
            return self.help()

        # Set the main hostname to find as context
        self.baseHostname = arguments.hostname

        # Have methods?
        if(not arguments.methods):
            # self.out(self.strings['errors']['empty-methods'])
            # self.out('') # Spacing to bottom
            # self.help()
            # return

            # Methods by default
            arguments.methods = '0123456789a'

        # Process each method (each character)
        for methodId in arguments.methods:

            if(methodId == '0'):
                self.methods.append(MethodAxfr(self))

            elif(methodId == '1'):
                self.methods.append(MethodDnsQueries(self))

            elif(methodId == '2'):
                self.methods.append(MethodVirusTotal(self))

            elif(methodId == '3'):
                self.methods.append(MethodRobtex(self))

            elif(methodId == '4'):
                self.methods.append(MethodCrtSh(self))

            elif(methodId == '5'):
                self.methods.append(MethodCertificateDetails(self))

            elif(methodId == '6'):
                self.methods.append(MethodGoogle(self))

            elif(methodId == '7'):
                self.methods.append(MethodBing(self))

            elif(methodId == '8'):
                self.methods.append(MethodDnsDumpster(self))

            elif(methodId == '9'):
                self.methods.append(MethodDictionary(
                    self,
                    'resources/dictionaries/dict-brute-4.txt',
                    self.strings['methods']['dictionary-4']['title']
                ))

            elif(methodId == 'a'):
                self.methods.append(MethodDictionary(
                    self,
                    'resources/dictionaries/dict-subdomains.txt',
                    self.strings['methods']['dictionary-words']['title']
                ))

            else:
                self.out(
                    message=self.strings['errors']['unknown-method'],
                    parseDict={
                        'method': methodId
                    }
                )
                self.out('') # Spacing to bottom
                self.help()
                return

        # Have metods?
        if(len(self.methods) == 0):
            self.out(self.strings['errors']['empty-methods'])
            return

        # Have filters?
        if(
            (arguments.filters is not None) and
            (len(arguments.filters) > 0)
        ):

            # Process each filter (each character)
            for filterId in arguments.filters:

                if(filterId == '0'):
                    self.filters.append(FilterPorts(self))

                elif(filterId == '1'):
                    self.filters.append(FilterHttpServices(self))

                else:
                    self.out(
                        message=self.strings['errors']['unknown-filter'],
                        parseDict={
                            'filter': filterId
                        }
                    )
                    self.out('') # Spacing to bottom
                    self.help()
                    return

        self.progress['methods']['total'] = len(self.methods)
        self.progress['filters']['total'] = len(self.filters)

        # Call all methods
        self.processAllMethods()

        # Have results?
        if(len(self.results.keys()) == 0):
            self.out(self.strings['result']['empty'])
            return

        # Sorted results by ip address
        self.results['ip-address']['items'] = (
            { k: v for k, v in sorted(self.results['ip-address']['items'].items()) }
        )

        # Sort hostnames
        for ipAddress in self.results['ip-address']['items'].keys():
            self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'] = (
                { k: v for k, v in sorted(self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'].items()) }
            )
        
        # TODO: Unimplemented.

        # Call all filters
        self.processAllFilters()

        # Show the results
        self.showResulsts()


    def processAllMethods(self):

        # Can continue to next method?
        self.canContinue = True

        # Start methods
        for methodClass in self.methods:

            # Increase the method count
            self.progress['methods']['current'] += 1

            # Find subdomains in the current method
            methodClass.find()

            # Free memory and call the destructor
            # For free local storage like as MethodVirusTotal.hostnames
            methodClass = None

            # Line spacing to bottom of method
            self.out('')

            if(not self.canContinue):
                break

    
    def processAllFilters(self):

        if(len(self.filters) == 0):
            # No filters found
            return

        # Can continue to next filter?
        self.canContinue = True

        # Start filters
        for filterClass in self.filters:

            # Increase the method count
            self.progress['filters']['current'] += 1

            # Filter all results
            filterClass.filterAll()

            # Free memory and call the destructor
            filterClass = None

            # Line spacing to bottom of method
            self.out('')

            if(not self.canContinue):
                break


    def showResulsts(self):

        # Show the results
        dt = datetime.utcnow().replace(tzinfo=pytz.utc).strftime('[%Y-%m-%d %H_%M_%S]')
        saveLogPath = 'subdomains_' + self.baseHostname + '_' + dt + '.log'

        # Print the header message
        self.out(self.strings['result']['result-all-title'])

        # Make nodes
        nodeRoot = self.makeNodes(self.results['ip-address'])

        # Final tree as string
        message = []

        for pre, fill, node in RenderTree(nodeRoot):
            message.append(
                self.parseString(
                    message=self.strings['result']['node-tree']['item-printed'],
                    parseDict={
                        'item': pre + str(node.name).strip()
                    }
                )
            )

        # Show tree
        self.out('\n'.join(message))

        # Newline as separator
        self.out('')
        self.out(
            message=self.strings['log-file']['saving'],
            parseDict={
                'path': saveLogPath
            }
        )

        # Save the tree
        fileHandler = open(saveLogPath, 'w') 
        fileHandler.write('\n'.join(message))
        fileHandler.close()

        # Free the memory
        message = None

        # Show the bottom result
        self.out(self.strings['result']['finish'])


    def makeNodes(self, data, parent=None):

        if(parent is None):
            # Main root
            root = Node(data['title'])
        else:
            # Branch
            root = Node(data['title'], parent=parent)

        # No items
        if(len(data['items'].keys()) == 0):
            return root

        for itemKey, itemValue in data['items'].items():
            if(
                isinstance(itemValue, dict) and
                ('title' in itemValue)
            ):
                self.makeNodes(itemValue, parent=root)

            else:
                Node(str(itemKey), root)

        return root


    def parseString(self, message, parseDict=None):

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

        return str(message)


    def out(self, message, parseDict=None, end='\n'):

        # Print the message
        print(self.parseString(message, parseDict), end=end)


    def addHostName(self, hostname, messageFormat=None):

        # Remove wilcards
        if(hostname.startswith('*.')):
            hostname = hostname[3:]

        ipAddress = None
        try:
            ipAddress = str(socket.gethostbyname(hostname))

        except Exception as e:
            ipAddress = 'unknown'

        # Make the stack with new ip address
        if(not ipAddress in self.results['ip-address']['items']):
            self.results['ip-address']['items'][ipAddress] = {
                'title' : (self.strings['result']['unknown-ip-address-key'] if ipAddress == 'unknown' else ipAddress),
                'items' : {
                    'hostnames': {
                        'title' : self.strings['result']['node-tree']['hostnames-title'],
                        'items' : { }
                    }
                }
            }
        
        # Hostname already exist in results?
        if(not hostname in self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items']):

            # Add host to ip address stack (as empty object for easy process in filters)
            self.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'][hostname] = None

            # Add to progress
            self.progress['total-hostnames'] += 1

            # Upgrade results
            self.results['ip-address']['title'] = self.parseString(
                message=self.strings['result']['node-tree']['root'],
                parseDict={
                    'count': self.progress['total-hostnames']
                }
            )

        # Quiet mode?
        if(messageFormat is None):
            return

        # Print the progress
        self.out(
            message=messageFormat,
            parseDict={
                'hostname'   : hostname,
                'ip-address' : (self.strings['result']['unknown-ip-address-key'] if ipAddress == 'unknown' else ipAddress)
            }
        )

        
    def help(self):

        self.out(
            message=self.strings['usage'],
            parseDict={
                'scriptname': str(sys.argv[0])
            }
        )


if __name__ == '__main__':
    try:
        controllerCls = Controller()

    except (KeyboardInterrupt, SystemExit):
        print('') # Clear current line
        exit(0)
