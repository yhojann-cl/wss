#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import threading
from modules.helpers.crawler import WCrawler


class FilterHttpServices(object):

    def __init__(self, context):

        # The main context
        self.context = context

        self.hostnameContext = {
            'check-ports'        : [ ],
            'threads-handlers'   : [ ],
            'current-hostname'   : None,
            'current-ip-address' : None
        }

        # Known http ports
        # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/managing_confined_services/sect-managing_confined_services-configuration_examples-changing_port_numbers
        # https://wiki.zimbra.com/wiki/Ports
        # https://geekflare.com/default-port-numbers/
        # https://confluence.atlassian.com/kb/ports-used-by-atlassian-applications-960136309.html
        self.defaultPortsToFind = list(set([ # set: Unique values
                80,   # Selinux http port
                443,  # Selinux http port
                488,  # Selinux http port
                8008, # Selinux http port
                8009, # Selinux http port
                8443, # Selinux http port
                8080, # Tomcat Startup
                8443, # Tomcat Startup (SSL)
                8005, # Tomcat Shutdown
                8009, # Tomcat AJP Connector
                8080, # GlassFish HTTP
                8181, # GlassFish HTTPS
                4848, # GlassFish Admin Server
                8080, # Jetty
                9000, # Jonas Admin Console
                8008, # IHS Administration
                8080, # JBoss Admin Console
                9990, # WildFly Admin Console
                7001, # WebLogic Admin Console
                9043, # WAS Admin Console (SSL
                9060, # WAS Admin Console
                9080, # WAS JVM HTTP
                9443, # WAS JVM HTTPS
                8080, # Alfresco Explorer/Share
                1527, # Apache Derby Network Server
                7777, # OHS
                4443, # OHS (SSL)
                8080, # Jenkins
                8081, # Macafee
                7001, # Nagios
                8081, # Nagios
                80,   # Zimbra mailbox/proxy
                443,  # Zimbra mailbox/proxy
                3443, # Zimbra proxy
                9071, # Zimbra proxy admin console 
                7047, # Zimbra conversion server
                7071, # Zimbra mailbox
                7072, # Zimbra mailbox
                7073, # Zimbra mailbox
                7780, # Zimbra mailbox spell check 
                8080, # Zimbra mailbox backend
                8443, # Zimbra mailbox backend
                8100, # Jira
                8015, # Jira
                5400, # VNC http
                5500, # VNC http
                5600, # VNC http
                5700, # VNC http
                5800, # VNC http
                3128, # Squid
                80,   # World Wide Web HTTP
                280,  # http-mgmt
                443,  # HTTPS
                488,  # gss-http
                591,  # FileMaker, Inc. - HTTP
                593,  # HTTP RPC Ep Map
                623,  # DMTF out-of-band web
                664,  # DMTF out-of-band secure web
                777,  # Multiling HTTP
                832,  # NETCONF for SOAP over HTTPS
                1001, # HTTP Web Push
                1183, # LL Surfup HTTP
                1184, # LL Surfup HTTPS
                2069, # HTTP Event Port
                2301, # Compaq HTTP
                2381, # Compaq HTTPS
                2688, # md-cf-http
                2851, # webemshttp
                3106, # Cardbox HTTP
                3227, # DiamondWave NMS Server
                3816, # Sun Local Patch Server
                4035, # WAP Push OTA-HTTP port
                4036, # WAP Push OTA-HTTP secure
                4180, # HTTPX
                4590, # RID over HTTP/TLS
                4848, # App Server - Admin HTTP
                4849, # App Server - Admin HTTPS
                5443, # Pearson HTTPS
                5554, # SGI ESP HTTP
                5985, # WBEM WS-Management HTTP
                5986, # WBEM WS-Management HTTP over
                5988, # WBEM CIM-XML (HTTP
                5989, # WBEM CIM-XML (HTTPS
                5990, # WBEM Export HTTPS
                6443, # Service Registry Default
                6480, # Service Registry Default
                6770, # PolyServe http
                6771, # PolyServe https
                6788, # SMC-HTTP
                6842, # Netmo HTTP
                7443, # Oracle Application Server
                7627, # SOAP Service Port
                7677, # Sun App Server - HTTPS
                7800, # Apple Software Restore
                8008, # HTTP Alternate
                8080, # HTTP Alternate (see port 80
                8088, # Radan HTTP
                8118, # Privoxy HTTP proxy
                8243, # Synapse Non Blocking HTTPS
                8280, # Synapse Non Blocking HTTP
                8443, # PCsync HTTPS
                8444, # PCsync HTTP
                8765, # Ultraseek HTTP
                8910, # manyone-http
                8990, # webmail HTTP service
                8991, # webmail HTTPS service
                9294, # ARMCenter http Service
                9295, # ARMCenter https Service
                9443, # WSO2 Tungsten HTTPS
                9762, # WSO2 Tungsten HTTP
                10880, # BVEssentials HTTP API
                11371, # OpenPGP HTTP Keyserver
                16992, # Intel(R) AMT SOAP/HTTP
                16993, # Intel(R) AMT SOAP/HTTPS
                20002, # Commtact HTTP
                20003, # Commtact HTTPS
                24680, # TCC User HTTP Service
                27504  # Kopek HTTP Head Port
            ]))


    def filterAll(self):

        # Header message
        self.context.out(
            message=self.context.strings['filter-begin'],
            parseDict={
                'current' : self.context.progress['filters']['current'],
                'total'   : self.context.progress['filters']['total'],
                'title'   : self.context.strings['filters']['http']['title']
            }
        )

        # For each ip address
        for ipAddress in self.context.results['ip-address']['items'].keys():

            if(ipAddress == 'unknown'):
                continue

            # For each hostname
            for hostname in self.context.results['ip-address']['items'][ipAddress]['items']['hostnames']['items'].keys():

                self.findHttpServices(ipAddress, hostname)


    def findHttpServices(self, ipAddress, hostname):

        # Hostname context (for multithreading)
        # Have ports scanned?
        if('ports' in self.context.results['ip-address']['items'][ipAddress]['items'].keys()):
            self.hostnameContext['check-ports'] = list(
                self.context.results['ip-address']['items'][ipAddress]['items']['ports']['items'].keys()
            )

        else:
            self.hostnameContext['check-ports'] = self.defaultPortsToFind

        self.hostnameContext['threads-handlers']   = [ ]
        self.hostnameContext['current-hostname']   = hostname
        self.hostnameContext['current-ip-address'] = ipAddress

        # 20 Threads by default
        for threadNumber in range(1, 20):

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
            message=self.context.strings['filters']['http']['progress-clear'],
            end=''
        )


    def threadCheck(self):

        while(True):

            if(len(self.hostnameContext['check-ports']) == 0):
                # No more ports
                break

            # Get next port
            port = int(self.hostnameContext['check-ports'].pop())

            for protocol in ['http', 'https']:

                # Omit conflicts
                if(
                    ((protocol == 'http') and (port == 443)) or
                    ((protocol == 'https') and (port == 80))
                ):
                    continue

                # Compose the final URL
                url = protocol + '://' + self.hostnameContext['current-hostname'] + '/'
                if(
                    ((protocol == 'http')  and (port != 80)) or
                    ((protocol == 'https') and (port != 443))
                ):
                    url = protocol + '://' + self.hostnameContext['current-hostname'] + ':' + str(port) + '/'

                self.context.out(
                    message=(
                        self.context.strings['filters']['http']['progress-clear'] +
                        self.context.strings['filters']['http']['progress']
                    ),
                    parseDict={
                        'url': url
                    },
                    end=''
                )

                # Use the crawler bot
                crawler = WCrawler()

                result = None
                try:
                    result = crawler.httpRequest(url)
                    crawler.clearContext()

                except Exception as e:
                    pass

                if(
                    # Unable to connect or reset/refused connection
                    (result is None) or

                    # Open port but is not a http service
                    (result['status-code'] == 0)
                ):
                    # Is not a HTTP service
                    continue

                # Get the content of the title tag
                matches = re.search(
                    br'<title>(.+?)<\/title>',
                    result['response-content'],
                    re.I | re.M
                )
                
                title = None
                if(matches):
                    title = str(matches.group(1))[2:][:-1]

                self.context.out(
                    message=(
                        self.context.strings['filters']['http']['progress-clear'] +
                        self.context.strings['filters']['http']['found'] + '\n' +
                        self.context.strings['filters']['http']['progress-wait']
                    ),
                    parseDict={
                        'url'   : url,
                        'title' : title
                    },
                    end=''
                )

                # Make results structure
                if(self.context.results['ip-address']['items'][self.hostnameContext['current-ip-address']]['items']['hostnames']['items'][self.hostnameContext['current-hostname']] is None):
                    self.context.results['ip-address']['items'][self.hostnameContext['current-ip-address']]['items']['hostnames']['items'][self.hostnameContext['current-hostname']] = {
                        'title': self.hostnameContext['current-hostname'],
                        'items': {
                            'http-services': {
                                'title' : self.context.strings['filters']['http']['node-tree']['http-title'],
                                'items' : { }
                            }
                        }
                    }

                # Make results structure from other filters
                if(not 'http-services' in self.context.results['ip-address']['items'][self.hostnameContext['current-ip-address']]['items']['hostnames']['items'][self.hostnameContext['current-hostname']]['items'].keys()):
                    self.context.results['ip-address']['items'][self.hostnameContext['current-ip-address']]['items']['hostnames']['items'][self.hostnameContext['current-hostname']]['items']['http-services'] = {
                        'title' : self.context.strings['filters']['http']['node-tree']['http-title'],
                        'items' : { }
                    }
                
                # Final line string
                nodeLine = self.context.parseString(
                    message=self.context.strings['filters']['http']['node-tree']['http-service'],
                    parseDict={
                        'title' : title,
                        'url'   : url
                    }
                )

                # Append to result
                if(not nodeLine in self.context.results['ip-address']['items'][self.hostnameContext['current-ip-address']]['items']['hostnames']['items'][self.hostnameContext['current-hostname']]['items']['http-services']['items'].keys()):
                    self.context.results['ip-address']['items'][self.hostnameContext['current-ip-address']]['items']['hostnames']['items'][self.hostnameContext['current-hostname']]['items']['http-services']['items'][nodeLine] = None
