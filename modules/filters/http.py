#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import threading

from modules.helpers.networking.crawler import WCrawler
from resources.util.helpers import Helper
from resources.util.constants import constants


class FilterHttpServices(object):

    ips = []
    webservices = []
    stack = []

    def __init__(self):
        # Puertos http conocidos. Fuentes:
        # https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
        # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/managing_confined_services/sect-managing_confined_services-configuration_examples-changing_port_numbers
        # https://wiki.zimbra.com/wiki/Ports
        # https://geekflare.com/default-port-numbers/
        # https://confluence.atlassian.com/kb/ports-used-by-atlassian-applications-960136309.html
        self.stack = [
            2069, 3106, 9762, 20002, 20003, 8243, 3128, 8765, 5700, 9294, 591,
            80, 593, 9295, 4180, 8280, 16992, 7777, 16993, 7780, 24680, 11371,
            623, 6770, 6771, 7800, 2688, 10880, 6788, 664, 3227, 1183, 1184,
            5800, 6842, 8910, 9443, 3816, 4848, 4849, 8443, 8444, 2301, 9990,
            777, 7443, 5400, 280, 8990, 8991, 2851, 9000, 6443, 832, 5443,
            8005, 8008, 8009, 2381, 8015, 6480, 9043, 7001, 4443, 5985, 5986,
            9060, 5988, 5989, 5990, 9071, 27504, 3443, 9080, 5500, 7047, 8080,
            8081, 8088, 7071, 7072, 7073, 8100, 5554, 8118, 443, 4035, 4036,
            7627, 5600, 488, 1001, 4590, 8181, 1527, 7677
        ]

    def findHttpServices(self, address):

        h = Helper()

        if ((h.ip_validate(address) is None)
                and (h.hostname_validate(address) is None)):
            return {}

        th = []

        for tn in range(1, 100):
            t = threading.Thread(target=self.check,
                                 kwargs={'address': address})
            t.setDaemon(True)
            th.append(t)

        for t in th:
            t.start()
            t.join()

        result = {
            'hostname': address,
            'addresses': h.resolve_dns(address),
            'webservices': self.webservices
        }

        return result

    def check(self, address):

        self.webservices = []
        while (len(self.stack)):
            port = self.stack.pop()
            for protocol in ['http', 'https']:

                # Omite conflictos
                if (((protocol == 'http') and (port == 443))
                        or ((protocol == 'https') and (port == 80))):
                    continue
                h = Helper()
                if (((protocol == 'http') and (port == 80))
                        or ((protocol == 'https') and (port == 443))):
                    continue
                url = h.formatter(
                    '{}://{}:{}/',
                    [protocol, address, str(port)])
                # Uso del crawler
                crawler = WCrawler()

                result = None
                try:
                    result = crawler.httpRequest(url)
                    crawler.clearContext()

                except Exception as e:
                    pass

                if (
                        # No fue posible conectar con el servidor
                    (result is None) or

                        # Puerto abierto pero no es un servicio HTTP
                    (result['status-code'] == 0)):
                    continue

                # Obtiene el contenido de la etiqueta HTML <title>
                matches = re.search(br'<title>(.+?)<\/title>',
                                    result['response-content'], re.I | re.M)

                title = None
                if (matches):
                    title = str(matches.group(1))[2:][:-1]

                sm = result.get('status-message', '-').decode()
                sc = result.get('status-code')
                t = title if title else ''

                self.webservices.append({
                    'url': url,
                    'title': t,
                    'status-code': sc,
                    'status-message': sm
                })
