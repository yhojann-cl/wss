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

        # El contexto principal
        self.context = context

        # Tiempo de espera por defecto para el módulo del socket
        socket.setdefaulttimeout = 0.50


    def find(self):

        # Mensaje de la cabecera del método
        self.context.out(
            message=self.context.strings['method-begin'],
            parseDict={
                'current' : self.context.progress['methods']['current'],
                'total'   : self.context.progress['methods']['total'],
                'title'   : self.context.strings['methods']['axfr']['title']
            }
        )

        self.context.out(
            self.context.strings['methods']['axfr']['getting-ns-servers']
        )

        # Obtiene el nombre de dominio FQDN base
        fqdn = self.context.baseHostname
        if(self.context.baseHostname.count('.') > 1):
            fqdn = '.'.join(self.context.baseHostname.split('.')[:-1])

        nameServers = []
        try:
            ans = dns.resolver.query(fqdn, 'NS', tcp=True)
            nameServers = [a.to_text().strip('.') for a in ans]
            nameServers = set(nameServers)    # Valores únicos
            nameServers = sorted(nameServers) # Valores ordenados

        except Exception as e:
            pass

        except dns.exception.DNSException as e:
            pass

        if(len(nameServers) == 0):
            self.context.out(
                self.context.strings['methods']['axfr']['unable-to-get-ns-servers']
            )
            return False

        # Procesa cada registro
        for nameServer in nameServers:
            if(
                (nameServer == self.context.baseHostname) or
                (not nameServer.endswith(self.context.baseHostname))
            ):
                continue

            # Nuevo subdominio encontrado
            self.context.addHostName(hostname=nameServer)

        self.context.out(
            self.context.strings['methods']['axfr']['making-axfr-queries']
        )

        # Revisa cada servidor NS
        for nameServer in nameServers:

            self.context.out(
                message=self.context.strings['methods']['axfr']['ns-progress'],
                parseDict={
                    'nameserver': nameServer
                },
                end=''
            )

            axfr = None
            try:
                # Crea la consulta AXFR
                axfr = dns.query.xfr(
                    where=nameServer,
                    zone=self.context.baseHostname,
                    lifetime=5.0 # En segundos
                )

            except Exception as e:
                # Imposible ejecutar la consulta DNS
                self.context.out(
                    self.context.strings['methods']['axfr']['ns-not-vulnerable']
                )
                continue

            zone = None
            try:
                # Intenta obtener los resultados de la consulta
                zone = dns.zone.from_xfr(axfr)
            
            except Exception as e:
                # Imposible obtener los registros
                self.context.out(
                    self.context.strings['methods']['axfr']['ns-not-vulnerable']
                )
                continue

            if zone is None:
                # Sin resultados
                self.context.out(
                    self.context.strings['methods']['axfr']['ns-not-vulnerable']
                )
                continue

            # El servidor actual NS es vulnerable
            self.context.out(
                    message=self.context.strings['methods']['axfr']['ns-vulnerable'],
                    parseDict={
                        'count': len(zone.nodes.items())
                    }
                )
            
            self.context.out(
                self.context.strings['methods']['axfr']['getting-items']
            )

            # Procesa cada resultado
            for name, node in zone.nodes.items():
                rdatasets = node.rdatasets

                for rdataset in rdatasets:

                    if(str(name) == '@'):
                        continue

                    # Agrega el subdominio encontrado a la pila global de resultados
                    self.context.addHostName(
                        hostname=str(name) + '.' + self.context.baseHostname,
                        messageFormat=self.context.strings['methods']['axfr']['item-found']
                    )
            
            # Finaliza todo, ya no es necesario seguir buscando
            self.context.canContinue = False
            break
