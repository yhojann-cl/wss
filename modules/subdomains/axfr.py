#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import dns.resolver
import dns.zone
import dns.exception
import dns.rdatatype
import dns.rdata

from resources.util.helpers import Helper


class MethodAxfr(object):

    ns = []
    subdomains = []

    def __init__(self):

        # Tiempo de espera por defecto para el módulo del socket
        socket.setdefaulttimeout = 0.50

    def find(self, hostname):
        h = Helper()
        
        nameServers = []
        try:
            ans = dns.resolver.query(hostname, 'NS', tcp=True)
            nameServers = [a.to_text().strip('.') for a in ans]
            nameServers = set(nameServers)  # Valores únicos
            nameServers = sorted(nameServers)  # Valores ordenados

        except Exception as e:
            pass

        except dns.exception.DNSException as e:
            pass

        if (len(nameServers) == 0):
            return {}

        # Procesa cada registro
        for ns in nameServers:
            self.ns.append(ns)
            axfr = None
            try:
                # Crea la consulta AXFR
                axfr = dns.query.xfr(where=ns, zone=hostname,lifetime=5.0)

            except Exception as e:
                continue

            zone = None
            try:
                # Intenta obtener los resultados de la consulta
                zone = dns.zone.from_xfr(axfr)

            except Exception as e:
                continue

            if zone is None:
                continue
            # Procesa cada resultado
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets

                for rdataset in rdatasets:

                    if (str(name) == '@'):
                        continue
                    r = h.formatter('{}.{}', [str(name), hostname])
                    self.subdomains.append(r)

        return {'ns': self.ns, 'domains': self.subdomains}